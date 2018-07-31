
# Redirections

def redirection(request):
    if request.user.is_authenticated:
        if request.user.is_staff | request.user.is_superuser:
            return True
        else:
            return False
    else:
        return False
