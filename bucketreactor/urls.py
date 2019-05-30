from django.conf.urls import *
from rest_framework.urlpatterns import format_suffix_patterns

from . import views

urlpatterns = (
    # Public
    url(r'^$', views.root),
    
    url(r'^user/auth/register/$', views.RegisterView.as_view(), name='user-register'),
    url(r'^user/auth/login/$', views.LoginView.as_view(), name='user-login'),
    url(r'^user/auth/logout/$', views.LogoutView.as_view(), name='user-logout'),
    url(r'^user/auth/password/change/$', views.PasswordChangeView.as_view(), name='user-password-change'),
    url(r'^user/auth/password/reset/$', views.PasswordResetView.as_view(), name='user-password-reset'),

    url(r'^user/box/$', views.BoxListCreateView.as_view(), name='user-node-view'),
    url(r'^user/box/(?P<identifier>([a-zA-Z0-9\_\-]+))/$', views.BoxUpdateView.as_view(), name='user-node-update'),
    url(r'^user/box/(?P<identifier>([a-zA-Z0-9\_\-]+))/measure/$', views.MeasurementListCreateView.as_view(), name='user-node-update')
)

urlpatterns = format_suffix_patterns(urlpatterns)
