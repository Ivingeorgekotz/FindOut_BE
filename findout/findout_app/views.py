from rest_framework import status
from rest_framework.views import APIView
from django.db import transaction
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer,PasswordChangeSerializer,DealerSerializer,CustomerSerializer,VehicleSerializer,ScheduleSerializer
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.generics import RetrieveUpdateDestroyAPIView,ListAPIView
from rest_framework.permissions import IsAuthenticated
from .models import Vehicle,Schedule
from rest_framework.exceptions import ValidationError
import logging
from drf_yasg.utils import swagger_auto_schema
from django.shortcuts import get_object_or_404
from rest_framework import generics
import requests
from requests.auth import HTTPBasicAuth
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import razorpay
from django.conf import settings
from drf_yasg import openapi


logger = logging.getLogger(__name__)

from django.http import JsonResponse, HttpResponseNotAllowed

@api_view(['GET'])
def unique_categories(request):
    if request.method == "GET":
        categories = Vehicle.objects.values_list('category', flat=True).distinct()
        unique_categories_list = list(categories)
        return JsonResponse({'categories': unique_categories_list})
    else:
        return HttpResponseNotAllowed(['GET'])


# @api_view(['GET'])
# def vehicles_by_category(request, category):
#     vehicles = Vehicle.objects.filter(category=category).prefetch_related('images')
#     vehicles_list = list(vehicles.values(
#         'id', 'user__email', 'category', 'type_of_vehicle',
#         'capacity', 'rent_per_hour', 'rent_per_week',
#         'rent_per_month', 'description', 'location','image_url'
#     ))
#     return JsonResponse({'vehicles': vehicles_list})


@api_view(['GET'])
def vehicles_by_category(request, category):
    vehicles = Vehicle.objects.filter(category=category).prefetch_related('images')
    data = []

    for vehicle in vehicles:
        # Retrieve the first image for the vehicle
        first_image = vehicle.images.first()
        image = first_image.image.url if first_image else None
        image_url = first_image.get_full_image_url() if first_image else None

        # Construct the custom response structure
        data.append({
            "id": vehicle.id,
            "image": image,
            "image_url": image_url,
            "category": vehicle.category,
            "type_of_vehicle": vehicle.type_of_vehicle,
            "capacity": vehicle.capacity,
            "rent_per_hour": str(vehicle.rent_per_hour),
            "rent_per_week": str(vehicle.rent_per_week),
            "rent_per_month": str(vehicle.rent_per_month),
            "description": vehicle.description,
            "location": vehicle.location,
        })

    return JsonResponse({'vehicles': data})


@api_view(['GET'])
def hello_world(request):
    return Response({'message': 'Hello, World!'})

User = get_user_model()


class CustomerSignupView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        data.update({
            'role': 'customer',
            'is_active': True,
            'is_staff': False,
            'is_superuser': False
        })

        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            with transaction.atomic():
                serializer.save()
            return Response({'message': 'Customer registered successfully!', 'status_code': 201, 'success': True},
                            status=status.HTTP_201_CREATED)

        logger.warning(f"Customer signup failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DealerSignupView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        data.update({
            'role': 'dealer',
            'is_active': True,
            'is_staff': False,
            'is_superuser': False
        })

        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            with transaction.atomic():
                serializer.save()
            return Response({'message': 'Dealer registered successfully!', 'status_code': 201, 'success': True},
                            status=status.HTTP_201_CREATED)

        logger.warning(f"Dealer signup failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    # Debug print statements
    logger.debug(f'Login attempt - Email: {email}')

    user = authenticate(request, email=email, password=password)

    if user is not None:
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'id':user.id,
            'email': user.email,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone_number': user.phone_number,
            'dealer_name': user.dealer_name,
            'gst_no': user.gst_no,
            'pan_card_no': user.pan_card_no,
            'is_superuser': user.is_superuser
        })

    logger.warning(f'Invalid login attempt - Email: {email}')
    return Response({'error': 'Invalid credentials', 'status_code': 401, 'success': False},
                    status=status.HTTP_401_UNAUTHORIZED)


class PasswordChangeView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordChangeSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password changed successfully!', 'status_code': 200, 'success': True},
                            status=status.HTTP_200_OK)

        logger.warning(f'Password change failed: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserPagination(PageNumberPagination):
    page_size = 10  # Number of users to show per page
    page_size_query_param = 'page_size'  # Allow clients to override this
    max_page_size = 100  # Set maximum limit for users per page

class UserListView(APIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get(self, request, *args, **kwargs):
        role = kwargs.get('role', None)
        search_query = request.query_params.get('q', None)
        order_by_param = request.query_params.get('order_by', 'id')  # Default sorting by 'id'
        order_dir = request.query_params.get('order_dir', 'asc')  # Default sorting direction 'asc'
        is_active_param = request.query_params.get('is_active', None)  # Filter by is_active status

        # Validate role
        if role not in ['dealer', 'customer', None]:
            return Response({
                'error': 'Invalid role specified',
                'status_code': 400,
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Filter users based on role
            users = User.objects.filter(role=role) if role else User.objects.all()

            # Filter by is_active status if provided
            if is_active_param is not None:
                users = users.filter(is_active=(is_active_param.lower() == 'true'))

            # Apply search query if provided
            if search_query:
                users = self.filter_users_by_search_query(users, role, search_query)

            # Handle sorting for multiple fields
            order_by_fields = order_by_param.split(',')
            if order_dir == 'desc':
                order_by_fields = [f'-{field}' for field in order_by_fields]
            users = users.order_by(*order_by_fields)

            # Pagination
            paginator = UserPagination()
            paginated_users = paginator.paginate_queryset(users, request)

            # Serialize data
            serializer = self.get_serializer(role, paginated_users)

            # Calculate total counts for customers and dealers
            totals = self.calculate_totals()

            # Return the response with total counts
            return paginator.get_paginated_response({
                'users': serializer.data,
                'totals': totals,
                'status_code': 200,
                'success': True
            })

        except Exception as e:
            logger.error(f"Error retrieving users: {str(e)}")
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def filter_users_by_search_query(self, users, role, search_query):
        """Filter users based on search query and role."""
        if role == 'dealer':
            return users.filter(
                Q(email__icontains=search_query) |
                Q(phone_number__icontains=search_query) |
                Q(dealer_name__icontains=search_query) |
                Q(gst_no__icontains=search_query)
            )
        elif role == 'customer':
            return users.filter(
                Q(email__icontains=search_query) |
                Q(phone_number__icontains=search_query) |
                Q(first_name__icontains=search_query) |
                Q(last_name__icontains=search_query) |
                Q(pan_card_no__icontains=search_query)
            )
        return users

    def get_serializer(self, role, paginated_users):
        """Get the appropriate serializer based on user role."""
        if role == 'dealer':
            return DealerSerializer(paginated_users, many=True)
        elif role == 'customer':
            return CustomerSerializer(paginated_users, many=True)
        else:
            raise ValueError("Role must be specified")

    def calculate_totals(self):
        """Calculate total counts for dealers and customers."""
        return {
            'total_dealers': User.objects.filter(role='dealer').count(),
            'total_active_dealers': User.objects.filter(role='dealer', is_active=True).count(),
            'total_inactive_dealers': User.objects.filter(role='dealer', is_active=False).count(),
            'total_customers': User.objects.filter(role='customer').count(),
            'total_active_customers': User.objects.filter(role='customer', is_active=True).count(),
            'total_inactive_customers': User.objects.filter(role='customer', is_active=False).count(),
        }



class ProfileView(RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Get the logged-in user
        return self.request.user

    def put(self, request, *args, **kwargs):
        try:
            return self.update(request, *args, **kwargs)
        except ValidationError as e:
            return Response({'errors': e.detail}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, *args, **kwargs):
        try:
            user = self.get_object()
            user.is_active = False
            user.save()
            return Response({'message': 'Profile deactivated successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request, *args, **kwargs):
        try:
            return self.partial_update(request, *args, **kwargs)
        except ValidationError as e:
            return Response({'errors': e.detail}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def refresh_access_token_view(request):
    refresh_token = request.data.get('refresh')

    if not refresh_token:
        return Response({'error': 'Refresh token is required', 'status_code': 400, 'success': False},
                        status=status.HTTP_400_BAD_REQUEST)

    try:
        refresh = RefreshToken(refresh_token)
        new_access_token = str(refresh.access_token)
        return Response({'access': new_access_token, 'status_code': 200, 'success': True})
    except Exception as e:
        return Response({'error': 'Invalid refresh token', 'status_code': 401, 'success': False},
                        status=status.HTTP_401_UNAUTHORIZED)


# @swagger_auto_schema(
#     method='post',
#     operation_description="Create a new vehicle",
#     request_body=VehicleSerializer,
#     responses={201: VehicleSerializer, 400: 'Bad Request'}
# )
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def create_vehicle(request):
#     """
#     Endpoint to create a new vehicle.
#     """
#     serializer = VehicleSerializer(data=request.data)
#     if serializer.is_valid():
#         # Automatically assign the authenticated user to the vehicle instance
#         serializer.save(user=request.user)
#         return Response(serializer.data, status=status.HTTP_201_CREATED)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
#
# class VehicleImageView(generics.ListCreateAPIView):
#     queryset = VehicleImage.objects.all()
#     serializer_class = VehicleImageSerializer
#     parser_classes = [MultiPartParser, FormParser]
#
#     def perform_create(self, serializer):
#         # Automatically assign the vehicle associated with the image
#         vehicle_id = self.request.data.get('vehicle')  # Get the vehicle ID from the request
#         vehicle = Vehicle.objects.get(id=vehicle_id)
#         serializer.save(vehicle=vehicle)
@swagger_auto_schema(
    method='post',
    operation_description="Create a new vehicle with images",
    request_body=VehicleSerializer,
    responses={201: VehicleSerializer, 400: 'Bad Request'}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_vehicle_with_images(request):
    """
    Endpoint to create a new vehicle with optional images.
    """
    serializer = VehicleSerializer(data=request.data, context={'request': request})

    if serializer.is_valid():
        # Automatically assign the authenticated user to the vehicle instance
        serializer.save(user=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_vehicles(request):
    """
    Endpoint to get all vehicles.
    """
    vehicles = Vehicle.objects.all()
    serializer = VehicleSerializer(vehicles, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def vehicle_detail(request, vehicle_id):
    """
    Endpoint to get, update, or delete a specific vehicle by its ID, including dealer details.
    """
    vehicle = get_object_or_404(Vehicle.objects.select_related('user'), id=vehicle_id)

    # GET request: retrieve vehicle details
    if request.method == 'GET':
        serializer = VehicleSerializer(vehicle)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # PUT request: update vehicle details
    elif request.method == 'PUT':
        serializer = VehicleSerializer(vehicle, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE request: delete the vehicle
    elif request.method == 'DELETE':
        vehicle.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_vehicles(request):
    """
    Endpoint to get all vehicles uploaded by the authenticated user.
    """
    user = request.user
    vehicles = Vehicle.objects.filter(user=user)
    serializer = VehicleSerializer(vehicles, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
# @permission_classes([IsAuthenticated, IsAdminUser])  # Ensure only admin users can access this view
@permission_classes([IsAuthenticated])  # Ensure only admin users can access this view

def get_vehicles_by_user_id(request, user_id):
    """
    Endpoint for admin to get all vehicles uploaded by a particular user using their user ID.
    """
    user = get_object_or_404(User, id=user_id)
    vehicles = Vehicle.objects.filter(user=user)
    serializer = VehicleSerializer(vehicles, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


class VehicleScheduleListView(generics.ListAPIView):
    serializer_class = ScheduleSerializer
    permission_classes = [IsAuthenticated]  # Adjust as needed

    def get_queryset(self):
        vehicle_id = self.kwargs['vehicle_id']
        return Schedule.objects.filter(vehicle_id=vehicle_id)

class ScheduleCreateView(generics.CreateAPIView):
    queryset = Schedule.objects.all()
    serializer_class = ScheduleSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        # Set the current authenticated user as the owner of the schedule
        serializer.save(user=self.request.user)

class DealerVehicleBookingsView(generics.ListAPIView):
    serializer_class = ScheduleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Get the logged-in user (dealer)
        user = self.request.user

        # Get all vehicles uploaded by the user (dealer)
        dealer_vehicles = Vehicle.objects.filter(user=user)

        # Get all schedules for those vehicles
        return Schedule.objects.filter(vehicle__in=dealer_vehicles)




class CreateOrderAPIView(APIView):
    @swagger_auto_schema(
        operation_description="Create a Razorpay order for payment",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'amount': openapi.Schema(type=openapi.TYPE_INTEGER, description='Amount in INR'),
            },
            required=['amount']
        ),
        responses={
            200: openapi.Response(
                description="Order created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'order_id': openapi.Schema(type=openapi.TYPE_STRING, description='Razorpay Order ID'),
                        'razorpay_key': openapi.Schema(type=openapi.TYPE_STRING, description='Razorpay API Key'),
                    }
                )
            ),
            400: "Bad Request",
        }
    )
    def post(self, request, *args, **kwargs):
        try:
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            data = request.data

            # Create an order
            order = client.order.create({
                "amount": int(data['amount']) * 100,  # Convert to paise
                "currency": "INR",
                "payment_capture": 1  # Auto capture after payment
            })

            return Response({"order_id": order['id'], "razorpay_key": settings.RAZORPAY_KEY_ID}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

def verify_payment(request):
    try:
        payload = request.data
        payment_id = payload['razorpay_payment_id']
        order_id = payload['razorpay_order_id']
        signature = payload['razorpay_signature']

        # Verify the signature
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        params = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature,
        }
        client.utility.verify_payment_signature(params)

        return JsonResponse({'status': 'success'})
    except razorpay.errors.SignatureVerificationError:
        return JsonResponse({'status': 'failed'}, status=400)

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json


@csrf_exempt
def razorpay_webhook(request):
    event = json.loads(request.body)

    if event['event'] == 'payment.captured':
        payment_id = event['payload']['payment']['entity']['id']
        amount = event['payload']['payment']['entity']['amount']
        # Process the payment (update your database, send email, etc.)
        return JsonResponse({'status': 'success'})

    return JsonResponse({'status': 'ignored'})
