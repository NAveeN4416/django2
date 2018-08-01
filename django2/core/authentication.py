from django.utils import timezone
from django.shortcuts import render,redirect
from django.http import HttpRequest, HttpResponse ,JsonResponse
from home.forms import SignUpForm
from django.contrib.auth import login as auth_login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.sessions.models import Session
from django.conf import settings
from django.contrib.auth.hashers import check_password


import os
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.template.loader import render_to_string
from .models import  auth_levels

####
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six

class TokenGenerator(PasswordResetTokenGenerator):
	def _make_hash_value(self, user, timestamp):
		return (
            	six.text_type(user.pk) + six.text_type(timestamp) +
            	six.text_type(user.username)  )

account_activation_token = TokenGenerator()
####

class Authentication:
  
    def signup(request):
        if request.method=='POST':
            form = SignUpForm(request.POST)
            if form.is_valid():
                form.save()
                username     = form.cleaned_data.get('username')
                raw_password = form.cleaned_data.get('password1')
                user = authenticate(username=username,password=raw_password)
                user.is_active = False
                user.save()

                if user is not None:
                    if user.is_active:
                        auth_login(request, user)
                        return redirect('index')
                    else:
                        messages.error(request,'Verify Email To Login')
                else:
                    messages.error(request,'username or password is incorrect')
                return redirect('login')
            else:
                return render(request,'registration/register.html',{'form':form})      
        else:
            form = SignUpForm()
            return render(request,'registration/register.html',{'form':form})        


    def login(request):
        if request.method == 'POST':
            form         = AuthenticationForm(request.POST)
            username     = request.POST['username']
            raw_password = request.POST['password']
            user = authenticate(username=username, password=raw_password)

            if user is not None:
                if user.is_active:
                    auth_login(request, user)
                    return redirect('index')
                else:
                    messages.error(request,'Verify Email To Login')
                    return redirect('login')
            else:
                messages.error(request,'username or password is incorrect')
                return redirect('login')
        else:
            if request.user.is_authenticated:
                return redirect('index')
            else:
                form = AuthenticationForm()
                return render(request,'registration/login.html',{'form':form})


    def logout(request,reason='1'):
        if request.user.is_authenticated:
            user_id = request.user.pk
            unexpired_sessions = Session.objects.filter(expire_date__gte=timezone.now())
            [
            session.delete() for session in unexpired_sessions
            if str(user_id) == session.get_decoded().get('_auth_user_id')
            ]

        if settings.LOGOUT_REASON==reason:
            messages.error(request,'You Can`t Access Admin Dashboard')
            settings.LOGOUT_REASON = ""

        return redirect('login')


    def authenticate(username, password):
        
        #Check For User Existance
        try:
            user        = User.objects.get(username=username)
            pwd_valid   = check_password(password, user.password)

            if pwd_valid:
                try:
                    user = User.objects.get(username=username)
                except User.DoesNotExist:
                    user = User(username=username)
                    user.is_staff = False
                    user.is_superuser = False
                    user.save()
                return user

            return None
        except User.DoesNotExist:
            return 0

class secure:
  
    def __init__(self):
      pass

    def send_email_verification(request,ref_id,path):
		
      user         = User.objects.get(pk=ref_id)
      current_site = get_current_site(request)
      mail_subject = 'Activate Your Django Account'
      message      = render_to_string('registration/verify_email.html', {
                                                              'user' 	: user.username,
                                                              'domain'  : current_site.domain,
                                                              'uid'	: urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                                                              'token'	: account_activation_token.make_token(user),
                                                              'path'    : path,
                                                              }
                                        )
      to_email     = user.email
      email        = EmailMessage(mail_subject, message, to=[to_email])

      if email.send():
        return 1
      else:
        return 0

    def verify_email(uidb64, token):
      try:
        uid  = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
      except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

      if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        if user.is_active:
          return user
        else:
          return 0
      else:
        return 1

    def password_changed(request,user):
      Subject = 'Subject'
      Body    = render_to_string('registration/chang_pass_success.html',{'user':user})
      email   = EmailMessage(Subject, Body, to=[user.email])
      if email.send():
        return 1
      else:
        return 0		


    
