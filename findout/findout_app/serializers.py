from rest_framework import serializers
from .models import User,Vehicle,VehicleImage,Schedule
from django.contrib.auth import get_user_model


class UserSerializer(serializers.ModelSerializer):
    # Password field is included for write operations only
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            'id', 'email', 'is_active', 'is_staff', 'is_superuser', 'role',
            'first_name', 'last_name', 'phone_number', 'dealer_name', 'gst_no', 'pan_card_no', 'password'
        ]
        extra_kwargs = {
            'first_name': {'required': False, 'allow_null': True},
            'last_name': {'required': False, 'allow_null': True},
            'phone_number': {'required': False, 'allow_null': True},
            'dealer_name': {'required': False, 'allow_null': True},
            'gst_no': {'required': False, 'allow_null': True},
            'pan_card_no': {'required': False, 'allow_null': True}
        }

    def create(self, validated_data):
        # Extract password from validated_data
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        # Extract password if present and handle separately
        print("Validated data:", validated_data)
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance



class PasswordChangeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    old_password = serializers.CharField(style={'input_type': 'password'})
    new_password = serializers.CharField(style={'input_type': 'password'}, min_length=8)

    def validate(self, data):
        email = data.get('email')
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        User = get_user_model()
        user = User.objects.filter(email=email).first()

        if user is None:
            raise serializers.ValidationError("User with this email does not exist.")

        if not user.check_password(old_password):
            raise serializers.ValidationError("Old password is incorrect.")

        if old_password == new_password:
            raise serializers.ValidationError("New password must be different from the old password.")

        return data

    def save(self, **kwargs):
        email = self.validated_data.get('email')
        new_password = self.validated_data.get('new_password')

        User = get_user_model()
        user = User.objects.filter(email=email).first()

        if user:
            user.set_password(new_password)
            user.save()


class DealerSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'email', 'phone_number', 'dealer_name', 'gst_no', 'role', 'is_active'
        ]

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'phone_number', 'pan_card_no', 'role', 'is_active'
        ]
#
#
# class VehicleSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Vehicle
#         exclude = ['user']
#
#
# class VehicleImageSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = VehicleImage
#         fields = ['id', 'vehicle', 'image']
class VehicleImageSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = VehicleImage
        fields = ['image', 'image_url']

    def get_image_url(self, obj):
        return obj.get_full_image_url()



class UserPublicInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone_number', 'email']


class VehicleSerializer(serializers.ModelSerializer):
    images = VehicleImageSerializer(many=True, required=False)
    dealer = UserPublicInfoSerializer(source='user', read_only=True)

    class Meta:
        model = Vehicle
        exclude = ['user']

    def create(self, validated_data):
        images_data = self.context['request'].FILES.getlist('images')
        vehicle = Vehicle.objects.create(**validated_data)

        for image in images_data:
            VehicleImage.objects.create(vehicle=vehicle, image=image)

        return vehicle


class UserPublicInfoSerializer_2(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']

class ScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Schedule
        fields = ['id', 'vehicle', 'start_date', 'end_date']
