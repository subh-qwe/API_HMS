<!DOCTYPE html>
<html>
<head>
    <title>Email Verification</title>
</head>
<body>
    <h1>Verify Your Email Address</h1>
    <p>Hi {{ $mailData['name'] }},</p>
    
    <p>Thanks for signing up! Please verify your email address using the OTP below:</p>
    
    <h2 style="font-size: 24px; letter-spacing: 5px; padding: 10px; background-color: #f0f0f0; display: inline-block;">{{ $mailData['otp'] }}</h2>
    
    <p>This OTP will expire in 10 minutes.</p>
    
    <p>If you did not create an account, no further action is required.</p>
</body>
</html>