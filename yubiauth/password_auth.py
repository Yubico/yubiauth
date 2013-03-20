__all__ = [
    'verify',
    'generate'
]

def validate(password, auth):
    try:
        (auth_type, auth_data) = auth.split(':', 1)
    except ValueError:
        return False
    if int(auth_type) is 0:
        return password == auth_data

    return False

def generate(password):
    return '0:%s' % (password)
