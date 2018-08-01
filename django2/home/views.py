# import Requirements Here

from django.shortcuts import render,redirect,reverse
from django.conf import settings
import os
import os.path import join
import datetime


from django.contrib.auth.models import User
#from .models import 
from django.http import HttResponse ,HttpRequest, JsonResponse



#=============================================

# Create your views here.

# Declare Models as Constants
constants = {
              'User' : User
              }
