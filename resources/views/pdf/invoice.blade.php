<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Booking Invoice</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .invoice-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .invoice-header h1 {
            color: #2c3e50;
            margin-bottom: 5px;
        }
        .invoice-info {
            margin-bottom: 20px;
        }
        .invoice-info p {
            margin: 5px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .total {
            text-align: right;
            font-weight: bold;
            font-size: 18px;
            margin-top: 20px;
        }
        .footer {
            margin-top: 50px;
            font-size: 12px;
            text-align: center;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="invoice-header">
        <h1>Booking Invoice</h1>
        <p>{{ $invoice_number }}</p>
        <p>Invoice Date: {{ $invoice_date }}</p>
    </div>
    
    <div class="invoice-info">
        <h2>Guest Information</h2>
        <p><strong>Name:</strong> {{ $guest->name }}</p>
        <p><strong>Email:</strong> {{ $guest->email }}</p>
    </div>
    
    <div class="invoice-info">
        <h2>Property Information</h2>
        <p><strong>Property:</strong> {{ $property->title }}</p>
        <p><strong>Address:</strong> {{ $property->address }}</p>
    </div>
    
    <div class="invoice-info">
        <h2>Booking Details</h2>
        <p><strong>Booking ID:</strong> {{ $booking->id }}</p>
        <p><strong>Check-in Date:</strong> {{ $booking->check_in_date }}</p>
        <p><strong>Check-out Date:</strong> {{ $booking->check_out_date }}</p>
        <p><strong>Number of Guests:</strong> {{ $booking->guests_count }}</p>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Description</th>
                <th>Days</th>
                <th>Rate per Night</th>
                <th>Amount</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Accommodation at {{ $property->name }}</td>
                <td>{{ $days }}</td>
                <td>₹ {{ number_format($property->price_per_night, 2) }}</td>
                <td>₹ {{ number_format($booking->total_price, 2) }}</td>
            </tr>
            <!-- Add taxes, fees, etc. as needed -->
        </tbody>
    </table>
    
    <div class="total">
        Total: ₹ {{ number_format($booking->total_price, 2) }}
    </div>
    
    <div class="footer">
        <p>Thank you for booking with us! If you have any questions regarding this invoice, please contact our support team.</p>
        <p>&copy; {{ date('Y') }} Stay Easy. All rights reserved.</p>
    </div>
</body>
</html>