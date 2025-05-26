<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Property Status Updated</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0; 
            padding: 0; 
            background-color: #f4f4f4;
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto; 
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header { 
            background: linear-gradient(135deg, #28a745, #20c997); 
            color: white; 
            padding: 30px 20px; 
            text-align: center; 
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 300;
        }
        .content { 
            padding: 30px 20px; 
        }
        .property-details { 
            background-color: #f8f9fa; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 8px; 
            border-left: 4px solid #28a745;
        }
        .status-badge {
            display: inline-block;
            background-color: #28a745;
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: bold;
            text-transform: uppercase;
            margin: 10px 0;
        }
        .highlight-box {
            background: linear-gradient(135deg, #e3f2fd, #f1f8e9);
            border: 2px solid #4caf50;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }
        .highlight-box h3 {
            color: #2e7d32;
            margin-top: 0;
            font-size: 20px;
        }
        .btn { 
            display: inline-block; 
            padding: 12px 25px; 
            background-color: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 15px 0;
            font-weight: bold;
        }
        .btn:hover {
            background-color: #0056b3;
        }
        .footer {
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            border-top: 1px solid #e9ecef;
            color: #6c757d;
            font-size: 14px;
        }
        .amenities-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 10px 0;
        }
        .amenity-tag {
            background-color: #007bff;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
        }
        .celebration {
            font-size: 48px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            @if($status === 'available')
                <h1>Congratulations!</h1>
                <p style="margin: 10px 0 0 0; font-size: 18px;">Your Property is Now Live!</p>
            @else
                <div class="celebration">📝</div>
                <h1>Property Status Updated</h1>
            @endif
        </div>
        
        <div class="content">
            <p>Dear {{ $host->name ?? $host->first_name ?? 'Host' }},</p>
            
            @if($status === 'available')
                <div class="highlight-box">
                    <h3>🚀 Your Property is Now Available for Listing!</h3>
                    <p style="margin: 0; font-size: 16px;">
                        Great news! Your property has been approved and is now live on our platform. 
                        Guests can discover and book your amazing space starting right now!
                    </p>
                </div>
                
                <p>We're excited to let you know that your property "<strong>{{ $property->title }}</strong>" has been successfully reviewed and approved by our team. It's now available for guests to discover and book!</p>
            @else
                <p>Your property "<strong>{{ $property->title }}</strong>" status has been updated.</p>
            @endif
            
            <div class="property-details">
                <h3>📍 Property Details:</h3>
                <p><strong>Title:</strong> {{ $property->title }}</p>
                <p><strong>Type:</strong> {{ ucfirst($property->property_type) }}</p>
                <p><strong>Location:</strong> {{ $property->address }}, {{ $property->city }}, {{ $property->state }} {{ $property->zip_code }}</p>
                <p><strong>Bedrooms:</strong> {{ $property->bedrooms }} | <strong>Bathrooms:</strong> {{ $property->bathrooms }}</p>
                <p><strong>Max Guests:</strong> {{ $property->max_guests }}</p>
                <p><strong>Price per Night:</strong> ₹ {{ number_format($property->price_per_night, 2) }}</p>
                
                <div class="status-badge text-bold">
                    Status: {{ ucfirst($status) }}
                </div>
                
                @if($property->amenities && $property->amenities->count() > 0)
                    <p><strong>Amenities:</strong></p>
                    <div class="amenities-list">
                       <ul>
                         @foreach($property->amenities as $amenity)
                            <li class="amenity-tag">{{ $amenity->name }}</li>
                        @endforeach
                       </ul>
                    </div>
                @endif
            </div>
            
            @if($status === 'available')
                <h3>🎯 What's Next?</h3>
                <ul style="line-height: 2;">
                    <li><strong>Manage Your Calendar:</strong> Keep your availability up to date</li>
                    <li><strong>Respond to Inquiries:</strong> Reply to guest messages promptly</li>
                    <li><strong>Prepare Your Space:</strong> Ensure your property is guest-ready</li>
                    <li><strong>Monitor Reviews:</strong> Provide excellent service for great reviews</li>
                </ul>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="#" class="btn">View Your Property Dashboard</a>
                </div>
                
                <div style="background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h4 style="color: #155724; margin-top: 0;">💡 Pro Tips for Success:</h4>
                    <ul style="color: #155724; margin-bottom: 0;">
                        <li>Upload high-quality photos to attract more guests</li>
                        <li>Write a detailed and welcoming property description</li>
                        <li>Respond to booking requests within 24 hours</li>
                        <li>Keep your pricing competitive for your area</li>
                    </ul>
                </div>
            @endif
            
            <p>If you have any questions about your property or need assistance with anything, our support team is here to help. Feel free to reach out to us anytime.</p>
            
            @if($status === 'available')
                <p>Welcome to our host community! We're thrilled to have you on board and look forward to helping you create amazing experiences for your guests.</p>
            @endif
            
            <p>Best regards,<br>
             <strong>Stay Easy Team</strong></p>
        </div>
        
        <div class="footer">
            <p>This email was sent regarding your property: {{ $property->title }}</p>
            <p>© {{ date('Y') }} Stay Easy Team. All rights reserved.</p>
        </div>
    </div>
</body>
</html>