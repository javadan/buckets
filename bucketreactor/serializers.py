import uuid

from rest_framework import serializers
from django.db import transaction
import json
import uuid

from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from allauth.account.models import EmailAddress
from allauth.account import app_settings
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.db import transaction
from django.contrib.auth import authenticate
from rest_auth.serializers import (
    PasswordChangeSerializer as DefaultPasswordChangeSerializer,
    PasswordResetSerializer as DefaultPasswordResetSerializer,
    PasswordResetConfirmSerializer as DefaultPasswordResetConfirmSerializer
)
from django.utils.translation import ugettext_lazy as _

from config import settings

from bucketreactor.models import  Box, Measurement, User
from bucketreactor.forms import PasswordResetForm
from bucketreactor.enums import *


class DateSerializer(serializers.ModelSerializer):
    created = serializers.SerializerMethodField()
    updated = serializers.SerializerMethodField()

    @staticmethod
    def get_created(obj):
        return int(obj.created.timestamp() * 1000)

    @staticmethod
    def get_updated(obj):
        return int(obj.updated.timestamp() * 1000)


class UserSerializer(DateSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'created', 'updated',)
        read_only_field = ('created', 'updated',)


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    user = UserSerializer()


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(required=False, allow_blank=True,
        max_length=50, write_only=True)
    last_name = serializers.CharField(required=False, allow_blank=True,
        max_length=50, write_only=True)
    password1 = serializers.CharField(required=True, write_only=True,
        max_length=128, style={'input_type': 'password'})
    password2 = serializers.CharField(required=True, write_only=True,
        max_length=128, style={'input_type': 'password'})

    def validate_email(self, email):
        return get_adapter().clean_email(email)

    def validate_password1(self, password):
        return get_adapter().clean_password(password)

    def validate(self, data):
        email = data.get('email')
        password1 = data.get('password1')
        password2 = data.get('password2')

        if password1 != password2:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    _("The two password fields don't match.")]})

        # Further email address validation related to the company.
        if EmailAddress.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError(
                {"email": [_("A user is already registered "
                             "with this email address.")]})

        return data

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.validated_data
        adapter.save_user(request, user, self)
        setup_user_email(request, user, [])
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True, allow_blank=False)
    password = serializers.CharField(max_length=128,
        style={'input_type': 'password'})

    def _validate_user(self, email, password):
        user = None

        if email and password:
            user = authenticate(email=email, password=password)
        else:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    _('Must include "email" and "password".')
                ]}
            )

        return  user

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        user = self._validate_user(email, password)

        if user:
            if not user.is_active:
                raise serializers.ValidationError(
                    {"non_field_errors": [_('User account is disabled.')]})
        else:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    _('Unable to log in with provided credentials.')
                ]})

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            if (app_settings.EMAIL_VERIFICATION
                    == app_settings.EmailVerificationMethod.MANDATORY):
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(
                        {"user": [_('Email is not verified.')]})

        attrs['user'] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    pass


class PasswordChangeSerializer(DefaultPasswordChangeSerializer):
    """
    Override the default serializer in order to mask the password fields.
    """
    old_password = serializers.CharField(
        max_length=128, style={'input_type': 'password'})
    new_password1 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})
    new_password2 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})


class PasswordResetSerializer(DefaultPasswordResetSerializer):
    password_reset_form_class = PasswordResetForm


class PasswordResetConfirmSerializer(DefaultPasswordResetConfirmSerializer):
    """
    Override the default serializer in order to mask the password fields.
    """
    new_password1 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})
    new_password2 = serializers.CharField(
        max_length=128, style={'input_type': 'password'})


class ResendVerifyEmailSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)


class VerifyEmailSerializer(serializers.Serializer):
    key = serializers.CharField(required=True)


class BoxSerializer(serializers.ModelSerializer):
    tag = serializers.CharField()
    identifier = serializers.UUIDField(read_only=True)
    class Meta:
        model = Box
        fields = (
            'identifier',
            'tag',
            'name',
            'description',
            'model',
        )
        read_only_fields = (
            'identifier',
            'user',
        )


class CreateBoxSerializer(BoxSerializer):
    tag = serializers.CharField()
    name = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    model = serializers.CharField()

    class Meta:
        model = BoxSerializer.Meta.model
        fields = BoxSerializer.Meta.fields
        read_only_fields = (
            'identifier',
            'user',
        )

    def validate(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return validated_data


class MeasurementSerializer(BoxSerializer):
    identifier = serializers.UUIDField(read_only=True)
    temperature = serializers.DecimalField(max_digits=10,decimal_places=2, required=False)
    humidity = serializers.DecimalField(max_digits=10,decimal_places=2,required=False)
    soil_moisture = serializers.DecimalField(max_digits=10,decimal_places=2,required=False)
    grow_light_state = serializers.BooleanField(required=False)
    fans_state = serializers.BooleanField(required=False)
    irrigation_state = serializers.BooleanField(required=False)
    grow_schedule = serializers.ChoiceField(
                    required=False,
                    source='grow_schedule.value',
                    choices=ScheduleType.choices())

    class Meta:
        model = Measurement
        fields = (
            'identifier',
            'temperature',
            'humidity',
            'soil_moisture',
            'grow_light_state',
            'fans_state',
            'irrigation_state',
            'grow_schedule',
        )

    def validate(self, validated_data):

        if validated_data.get('grow_schedule'):
            grow_schedule = validated_data['grow_schedule']['value']
            validated_data['grow_schedule'] = ScheduleType(grow_schedule)

        try:
            box = Box.objects.get(
                identifier = self.context["identifier"],
            )
        except Box.DoesNotExist:
            raise exceptions.NotFound()

        validated_data['box'] = box
        return validated_data
