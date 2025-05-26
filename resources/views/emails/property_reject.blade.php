<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Property Listing Rejected</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .container {
            background-color: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
        }
        .content {
            margin-bottom: 30px;
        }
        .property-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #e74c3c;
        }
        .contact-info {
            background-color: #e8f4fd;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #3498db;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 14px;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 10px 0;
        }
        .rejection-notice {
            color: #e74c3c;
            font-weight: bold;
            font-size: 18px;
            text-align: center;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo"></div>
            <h2>Property Listing Status Update</h2>
        </div>

        <div class="content">
            <p>Dear {{ $propertyHost->host->name ?? 'Host' }},</p>

            <div class="rejection-notice">
                ❌ Your Property Has Been Rejected
            </div>

            <p>We regret to inform you that your property listing has been rejected after our review process.</p>

            <div class="property-info">
                <h3>Property Details:</h3>
                <p><strong>Property Title:</strong> {{ $propertyHost->title ?? 'Your Property' }}</p>
                <p><strong>Property Type:</strong> {{ ucfirst($propertyHost->property_type ?? 'Property') }}</p>
                <p><strong>Location:</strong> {{ $propertyHost->address ?? 'N/A' }}, {{ $propertyHost->city ?? 'N/A' }}, {{ $propertyHost->state ?? 'N/A' }}</p>
                <p><strong>Bedrooms:</strong> {{ $propertyHost->bedrooms ?? 'N/A' }} | <strong>Bathrooms:</strong> {{ $propertyHost->bathrooms ?? 'N/A' }} | <strong>Max Guests:</strong> {{ $propertyHost->max_guests ?? 'N/A' }}</p>
                <p><strong>Price per Night:</strong> ${{ number_format($propertyHost->price_per_night ?? 0, 2) }}</p>
                <p><strong>Status:</strong> <span style="color: #e74c3c;">Rejected</span></p>
            </div>

            <p>Your property listing did not meet our current listing standards or platform requirements. This could be due to various reasons including:</p>
            
            <ul>
                <li>Incomplete property information</li>
                <li>Insufficient or poor quality photos</li>
                <li>Pricing concerns</li>
                <li>Location verification issues</li>
                <li>Property condition or safety concerns</li>
                <li>Non-compliance with local regulations</li>
            </ul>

            <div class="contact-info">
                <h3>☎ Need Assistance?</h3>
                <p>If you have questions about this rejection or would like to discuss how to improve your listing for resubmission, please don't hesitate to contact our Stay Easy admin team.</p>
                
                <p><strong>Contact Options:</strong></p>
                <ul>
                    <li><strong>Email:</strong> admin@stayeasy.com</li>
                    <li><strong>Phone:</strong> +1 (555) 123-4567</li>
                    <li><strong>Support Hours:</strong> Monday - Friday, 9:00 AM - 6:00 PM</li>
                </ul>
                
                <p>Our team is ready to help you understand the requirements and guide you through the process of creating a successful property listing.</p>
            </div>

            <p>We appreciate your interest in partnering with Stay Easy and encourage you to reach out to our admin team for guidance on resubmitting your property listing.</p>

            <p>Thank you for choosing Stay Easy.</p>

            <p>Best regards,<br>
            <strong>The Stay Easy Team</strong></p>
        </div>

        <div class="footer">
            <p>&copy; {{ date('Y') }} Stay Easy. All rights reserved.</p>
            <p>This is an automated message. Please do not reply directly to this email.</p>
        </div>
    </div>
</body>
</html>