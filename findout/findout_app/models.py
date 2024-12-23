from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    role = models.CharField(max_length=10, blank=True)  # To distinguish between roles
    first_name = models.CharField(max_length=255, null=True, blank=True)
    last_name = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    dealer_name = models.CharField(max_length=255, null=True, blank=True)
    gst_no = models.CharField(max_length=15, null=True, blank=True)
    pan_card_no = models.CharField(max_length=10, null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class Vehicle(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    category = models.CharField(max_length=50, null=True, blank=True)
    type_of_vehicle = models.CharField(max_length=50, null=True, blank=True)
    capacity = models.PositiveIntegerField(null=True, blank=True)
    rent_per_hour = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rent_per_week = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rent_per_month = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"{self.category} - {self.type_of_vehicle} - {self.user.email if self.user else 'No User'}"


class VehicleImage(models.Model):
    vehicle = models.ForeignKey(Vehicle, related_name='images', on_delete=models.CASCADE)
    image = models.FileField(upload_to='vehicles/', blank=True, null=True)

    def __str__(self):
        return f"Image for {self.vehicle.category} - {self.vehicle.type_of_vehicle}"

    def get_full_image_url(self):
        return f"{settings.SITE_URL}{self.image.url}"


class Schedule(models.Model):
    vehicle = models.ForeignKey('Vehicle', related_name='schedules', on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return f"Schedule for {self.vehicle.category} - {self.vehicle.type_of_vehicle} from {self.start_date} to {self.end_date}"

    def clean(self):
        if self.start_date > self.end_date:
            raise ValidationError('End date must be after or equal to start date.')

        # overlapping_schedule = Schedule.objects.filter(
        #     vehicle=self.vehicle,
        #     start_date__lte=self.end_date,
        #     end_date__gte=self.start_date
        # ).exclude(id=self.id)
        #
        # if overlapping_schedule.exists():
        #     raise ValidationError('This vehicle is already scheduled for this date range.')

    def save(self, *args, **kwargs):
        self.clean()
        super(Schedule, self).save(*args, **kwargs)