from django.urls import path
from .views import CustomerSignupView, DealerSignupView,login_view,PasswordChangeView,UserListView, CreateOrderAPIView
from .views import hello_world,ProfileView,refresh_access_token_view, razorpay_webhook, verify_payment
from . import views




urlpatterns = [
    path('signup/customer/', CustomerSignupView.as_view(), name='customer-signup'),
    path('signup/dealer/', DealerSignupView.as_view(), name='dealer-signup'),
    path('login/', login_view, name='login'),
    path('change-password/', PasswordChangeView.as_view(), name='change_password'),
    path('dealers/', UserListView.as_view(), {'role': 'dealer'}, name='dealer-list'),
    path('customers/', UserListView.as_view(), {'role': 'customer'}, name='customer-list'),
    path('hello/', hello_world, name='hello-world'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('token/refresh/', refresh_access_token_view, name='token_refresh'),
    # path('vehicles/', views.create_vehicle, name='create-vehicle'),
    # path('vehicle-images/', VehicleImageView.as_view(), name='vehicle-image-list-create'),
    path('vehicles/', views.create_vehicle_with_images, name='create-vehicle-with-images'),
    path('vehicles/all/', views.get_all_vehicles, name='get-all-vehicles'),  # New path for getting all vehicles
    path('vehicles/<int:vehicle_id>/', views.vehicle_detail, name='get-vehicle-detail'),
    path('vehicles/user/', views.get_user_vehicles, name='get-user-vehicles'),  # New path for user's vehicles
    path('vehicles/user/<int:user_id>/', views.get_vehicles_by_user_id, name='get-vehicles-by-user-id'),
    path('schedules/create/', views.ScheduleCreateView.as_view(), name='schedule-create'),
    path('schedules/vehicle/<int:vehicle_id>/', views.VehicleScheduleListView.as_view(), name='vehicle-schedule-list'),
    path('dealer/bookings/', views.DealerVehicleBookingsView.as_view(), name='dealer-vehicle-bookings'),
    path('create-order/', CreateOrderAPIView.as_view(), name='create-order'),
    path('verify-payment/', verify_payment, name='verify-payment'),
    path('webhook/', razorpay_webhook, name='razorpay-webhook'),
    path('unique-categories/', views.unique_categories, name='unique_categories'),
    path('vehicles/<str:category>/', views.vehicles_by_category, name='vehicles_by_category'),
    # path('send-whatsapp/', SendWhatsAppMessageView.as_view(), name='send-whatsapp'),
    # path('send-whatsapp/', SendWhatsAppMessageView.as_view(), name='send-whatsapp'),

    # New path for admin to view a user's vehicles
    # New path for individual vehicles

]

