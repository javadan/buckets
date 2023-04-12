from django.urls import include, re_path
from django.contrib import admin
from django.conf import settings
from django.contrib.auth.views import *

from . import views

import debug_toolbar

admin.autodiscover()

app_name = 'bucketreactor'

urlpatterns = (
    # Views
    re_path(r'^api/', include('bucketreactor.urls', namespace='bucketreactor')),
    re_path(r'^admin/', admin.site.urls),
)

# Add debug URL routes
if settings.DEBUG:
    urlpatterns = (
        re_path(r'^$', views.index, name='index'),
        re_path(r'^__debug__/', include(debug_toolbar.urls)),
    ) + urlpatterns
