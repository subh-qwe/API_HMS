<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Booking Confirmation</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
        }
        .booking-details {
            background-color: #f9f9f9;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .booking-details p {
            margin: 5px 0;
        }
        .cta-button {
            display: inline-block;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .footer {
            margin-top: 30px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Booking Confirmation</h1>
        <p>Thank you for your booking!</p>
    </div>
    
    <p>Dear {{ $booking->guest->name }},</p>
    
    <p>Your booking has been confirmed. <br>Please find the details attached PDF for your booking Invoice :</p>
        
    <p>If you need to make any changes to your booking or have any questions, please don't hesitate to contact us.</p>
    
    <p>We look forward to hosting you!</p>
    
    <p>Best regards,<br>With Stay Easy Team</p>
    
    <div class="footer">
        <p>&copy; {{ date('Y') }} Stay Easy. All rights reserved.</p>
        <p>This email was sent to {{ $booking->guest->email }}</p>
    </div>
</body>
</html>