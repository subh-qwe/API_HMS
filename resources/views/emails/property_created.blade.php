<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Property Created - Verification</title>
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; padding: 20px; color: #333;">

    <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <h2 style="color: #2c3e50;">Hi {{ $hostid->name }},</h2>

        <p style="font-size: 16px;">
            We're excited to let you know that your property has been successfully created on our platform! 🎉
        </p>

        <h3 style="margin-top: 30px; color: #34495e;">🏡 Property Summary:</h3>
        <table cellpadding="8" cellspacing="0" width="100%" style="border-collapse: collapse; font-size: 15px;">
            <tr>
                <td><strong>Title:</strong></td>
                <td>{{ $property->title }}</td>
            </tr>
            <tr>
                <td><strong>Type:</strong></td>
                <td>{{ ucfirst($property->property_type) }}</td>
            </tr>
            <tr>
                <td><strong>Location:</strong></td>
                <td>{{ $property->address }}, {{ $property->city }}, {{ $property->state }} - {{ $property->zip_code }}</td>
            </tr>
            <tr>
                <td><strong>Price/Night:</strong></td>
                <td>₹{{ number_format($property->price_per_night, 2) }}</td>
            </tr>
            <tr>
                <td><strong>Max Guests:</strong></td>
                <td>{{ $property->max_guests }}</td>
            </tr>
            <tr>
                <td><strong>Status:</strong></td>
                <td>{{ ucfirst($property->status) }}</td>
            </tr>
        </table>

        <p style="font-size: 16px; margin-top: 25px;">
            <strong>What's Next?</strong><br>
            Our team will now review and verify your property details. Once verified, your listing will go live on the Stay Easy app, making it visible to travelers across our platform.
        </p>

        <p style="font-size: 16px; margin-top: 20px;">
            We’ll notify you as soon as your property has been approved. In the meantime, feel free to log in and update your listing or add more details/photos.
        </p>

        <p style="margin-top: 30px;">
            Thank you for partnering with us to make travel easier and more welcoming for everyone.
        </p>

        <p style="font-weight: bold; color: #2c3e50;">– The Stay Easy Team</p>
    </div>

</body>
</html>
