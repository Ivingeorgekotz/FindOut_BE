from django.contrib import admin
from .models import Vehicle, VehicleImage

@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ('category', 'type_of_vehicle', 'capacity', 'rent_per_hour', 'user')
    search_fields = ('category', 'type_of_vehicle', 'user__email')

@admin.register(VehicleImage)
class VehicleImageAdmin(admin.ModelAdmin):
    list_display = ('vehicle',)
