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


class Authentication():
  
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
            
    
