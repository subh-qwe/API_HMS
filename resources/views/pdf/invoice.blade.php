<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Booking Invoice</title>
    <style>
        body {
            font-family: 'Helvetica', Arial, sans-serif;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #fff;
        }
        .container {
            padding: 40px;
            max-width: 800px;
            margin: 0 auto;
        }
        .invoice-header {
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            margin-bottom: 30px;
            position: relative;
        }
        .invoice-title {
            color: #2c3e50;
            font-size: 28px;
            font-weight: 700;
            margin: 0;
        }
        .invoice-subtitle {
            color: #7f8c8d;
            font-size: 16px;
        }
        .company-logo {
            position: absolute;
            top: 0;
            right: 0;
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }
        .invoice-details {
            margin-bottom: 25px;
            background: #f1f1f1;
            padding: 15px;
            border-radius: 4px;
        }
        .info-section {
            margin-bottom: 30px;
            display: flex;
            flex-direction: column; 
            gap: 20px; 
        }

        .info-box {
            width: 100%; 
            box-sizing: border-box;
            margin-bottom: 20px; 
        }

        
        .info-box:last-child {
            margin-right: 0;
        }

        /* Add a clearfix to ensure both info boxes stay within the container */
        .info-section::after {
            content: "";
            display: table;
            clear: both;
        }
        .section-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        .info-item {
            margin-bottom: 10px;
        }
        .info-label {
            font-weight: bold;
            color: #34495e;
        }
        .info-value {
            color: #555;
        }
        .dates-highlight {
            background-color: #ebf5fb;
            border-left: 4px solid #3498db;
            padding: 10px 15px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        thead {
            background-color: #3498db;
            color: white;
        }
        th, td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .total-amount {
            text-align: right;
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .page-break {
            page-break-before: always;
        }
        .payment-instructions {
            background-color: #ebf5fb;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .thank-you {
            text-align: center;
            font-size: 20px;
            color: #3498db;
            font-weight: bold;
            margin: 30px 0;
        }
        .footer {
            border-top: 1px solid #ddd;
            padding-top: 20px;
            text-align: center;
            font-size: 12px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="invoice-header">
            <div class="company-logo">Stay Easy</div>
            <h1 class="invoice-title">BOOKING INVOICE</h1>
            <p class="invoice-subtitle">Your home away from home</p>
        </div>

        <div class="invoice-details">
            <p><strong>Invoice #:</strong> {{ $invoice_number }}</p>
            <p><strong>Issue Date:</strong> {{ \Carbon\Carbon::parse($invoice_date)->format('d M Y') }}</p>
        </div>

        <div class="info-section">
    <div class="info-box">
        <div class="section-title">Guest Information</div>
        <div class="info-item">
            <div class="info-label">Name:</div>
            <div class="info-value">{{ $guest->name }}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Email:</div>
            <div class="info-value">{{ $guest->email }}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Phone:</div>
            <div class="info-value">{{ $guest->phone_number ?? 'Not provided' }}</div>
        </div>
    </div>

    <div class="info-box">
        <div class="section-title">Property Details</div>
        <div class="info-item">
            <div class="info-label">Property Name:</div>
            <div class="info-value">{{ $property->title }}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Address:</div>
            <div class="info-value">{{ $property->address }}</div>
        </div>
        <div class="info-item">
            <div class="info-label">Property Type:</div>
            <div class="info-value">{{ $property->type ?? 'Standard' }}</div>
        </div>
    </div>
</div>

        <div class="section">
            <div class="section-title">Booking Details</div>
            <div class="dates-highlight">
                <p><strong>Check-in:</strong> {{ \Carbon\Carbon::parse($booking->check_in_date)->format('d M Y') }}</p>
                <p><strong>Check-out:</strong> {{ \Carbon\Carbon::parse($booking->check_out_date)->format('d M Y') }}</p>
                <p><strong>Length of Stay:</strong> {{ $days }} {{ $days > 1 ? 'nights' : 'night' }}</p>
                <p><strong>Guests:</strong> {{ $booking->guests_count }} {{ $booking->guests_count > 1 ? 'persons' : 'person' }}</p>
            </div>
        </div>

        <div class="page-break"></div>
        <div class="section">
            <div class="section-title">Charges</div>
            <table>
                <thead>
                    <tr>
                        <th>Description</th>
                        <th>Rate/Night</th>
                        <th>Nights</th>
                        <th>Amount</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Accommodation at {{ $property->title }}</td>
                        <td>Rs. {{ number_format($property->price_per_night, 2) }}</td>
                        <td>{{ $days }}</td>
                        <td>Rs. {{ number_format($property->price_per_night * $days, 2) }}</td>
                    </tr>
                    @if(isset($property->cleaning_fee) && $property->cleaning_fee > 0)
                        <tr>
                            <td>Cleaning Fee</td>
                            <td>-</td>
                            <td>-</td>
                            <td>Rs. {{ number_format($property->cleaning_fee, 2) }}</td>
                        </tr>
                    @endif
                    @if(isset($property->service_fee) && $property->service_fee > 0)
                        <tr>
                            <td>Service Fee</td>
                            <td>-</td>
                            <td>-</td>
                            <td>Rs. {{ number_format($property->service_fee, 2) }}</td>
                        </tr>
                    @endif
                </tbody>
                <tfoot>
                    <tr>
                        <td colspan="3">Total Amount:</td>
                        <td>INR {{ number_format($property->price_per_night * $days + $property->cleaning_fee + $property->service_fee, 2) }}</td>
                    </tr>
                </tfoot>
            </table>
        </div>

        <div class="payment-instructions">
            <p><strong>Payment Status:</strong> {{ strtoupper($invoice->status) }}</p>
            <p>Please complete the payment before check-in. For queries, contact support.</p>
        </div>

        <div class="thank-you">Thank You for Choosing Stay Easy!</div>

        <div class="footer">
            <p>This is a computer-generated invoice and doesn't require a signature.</p>
            <p>&copy; {{ date('Y') }} Stay Easy. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
