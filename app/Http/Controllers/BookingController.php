<?php

namespace App\Http\Controllers;

use App\Models\bookings;
use App\Models\Invoice;
use App\Models\Properties;
use Illuminate\Support\Facades\Mail;
use App\Mail\BookingInvoiceMail;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use PDF; 

class BookingController extends Controller
{
    /**
     * Book a property
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function bookProperty(Request $request)
    {
        // Validate request data
        $validator = Validator::make($request->all(), [
            'property_id' => 'required|exists:properties,id',
            'check_in_date' => 'required|date|after_or_equal:today',
            'check_out_date' => 'required|date|after:check_in_date',
            'guests_count' => 'required|integer|min:1',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        // Get authenticated user as guest
        $guest_id = Auth::id();
        
        // Check if property exists and is available for the selected dates
        $property = Properties::find($request->property_id);
        if (!$property) {
            return response()->json([
                'status' => 'error',
                'message' => 'Property not found'
            ], 404);
        }
        
        // Check for availability
        $existingBookings = bookings::where('property_id', $request->property_id)
            ->where(function($query) use ($request) {
                $query->whereBetween('check_in_date', [$request->check_in_date, $request->check_out_date])
                    ->orWhereBetween('check_out_date', [$request->check_in_date, $request->check_out_date])
                    ->orWhere(function($q) use ($request) {
                        $q->where('check_in_date', '<=', $request->check_in_date)
                          ->where('check_out_date', '>=', $request->check_out_date);
                    });
            })
            ->where('status', '!=', 'cancelled')
            ->count();
            
        if ($existingBookings > 0) {
            return response()->json([
                'status' => 'error',
                'message' => 'Property not available for the selected dates'
            ], 400);
        }
        
        // Calculate total price (number of days * property price)
        $checkInDate = new \DateTime($request->check_in_date);
        $checkOutDate = new \DateTime($request->check_out_date);
        $days = $checkInDate->diff($checkOutDate)->days;
        
        // Include all fees in total price for consistency
        $base_price = $days * $property->price_per_night;
        $cleaning_fee = $property->cleaning_fee ?? 0;
        $service_fee = $property->service_fee ?? 0;
        $total_price = $base_price + $cleaning_fee + $service_fee;
        
        try {
            // Use a transaction to ensure booking and invoice are created together
            $booking = DB::transaction(function() use ($request, $guest_id, $total_price, $days, $property) {
                
                // Create booking
                $booking = bookings::create([
                    'property_id' => $request->property_id,
                    'guest_id' => $guest_id,
                    'check_in_date' => $request->check_in_date,
                    'check_out_date' => $request->check_out_date,
                    'guests_count' => $request->guests_count,
                    'total_price' => $total_price,
                    'status' => 'pending'
                ]);
                
                // Load relationships for the invoice creation
                $booking->load('property', 'guest');
                
                // Create invoice record in the database
                $invoice_number = 'INV' . date('Y') . '-' . str_pad($booking->id, 6, '0', STR_PAD_LEFT);
                $base_price = $days * $property->price_per_night;
                
                Invoice::create([
                    'booking_id' => $booking->id,
                    'invoice_number' => $invoice_number,
                    'subtotal' => $base_price,
                    'cleaning_fee' => $property->cleaning_fee ?? 0,
                    'service_fee' => $property->service_fee ?? 0,
                    'total' => $total_price,
                    'status' => 'unpaid'
                ]);
                
                return $booking;
            });
            
            // Generate PDF invoice
            $invoicePdf = $this->generateInvoicePdf($booking);
            
            // Save PDF to storage
            $invoicePath = storage_path('app/public/booking_' . $booking->id . '.pdf');
            file_put_contents($invoicePath, $invoicePdf->output());
    
            // Send booking invoice email with PDF attachment
            try {
                Mail::to($booking->guest->email)->send(new BookingInvoiceMail($booking, $invoicePath));
            } 
            catch (\Exception $e) {
                // Log error but don't fail the request
                \Log::error('Failed to send booking invoice email: ' . $e->getMessage());
                
                // You might want to queue the email for retry
                // Mail::to($booking->guest->email)->queue(new BookingInvoiceMail($booking, $invoicePath));
            }
            
            return response()->json([
                'status' => 'success',
                'message' => 'Booking created successfully',
                'data' => [
                    'booking_id' => $booking->id,
                    'property_id' => $booking->property_id,
                    'check_in_date' => $booking->check_in_date,
                    'check_out_date' => $booking->check_out_date,
                    'guests_count' => $booking->guests_count,
                    'total_price' => $booking->total_price,
                    'status' => $booking->status
                ]
            ], 201);
        }
        catch (\Exception $e) {
            \Log::error('Failed to create booking or invoice: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to create booking. Please try again later.'
            ], 500);
        }
    }
    
 
    private function generateInvoicePdf(bookings $booking)
    {
        // Make sure the property and guest relations are loaded
        if (!$booking->relationLoaded('property')) {
            $booking->load('property');
        }
        
        if (!$booking->relationLoaded('guest')) {
            $booking->load('guest');
        }
        
        // Get the invoice from database
        $invoice = Invoice::where('booking_id', $booking->id)->first();
        
        if (!$invoice) {
            throw new \Exception('Invoice not found for booking #' . $booking->id);
        }
        
        $data = [
            'booking' => $booking,
            'property' => $booking->property,
            'guest' => $booking->guest,
            'invoice' => $invoice,
            'invoice_number' => 'INV' . date('Y') . rand(0, 999) . str_pad($booking->id, 4, '0', STR_PAD_LEFT),
            'invoice_date' => date('Y-m-d'),
            'days' => (new \DateTime($booking->check_in_date))->diff(new \DateTime($booking->check_out_date))->days,
        ];
        
        // Generate PDF using Laravel-DomPDF
        $pdf = PDF::loadView('pdf.invoice', $data);
        
        return $pdf;
    }
    
    /**
     * Cancel a booking
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function cancelBooking(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'booking_id' => 'required|exists:bookings,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }
        
        $booking = bookings::find($request->booking_id);
        
        // Check if user owns this booking
        if ($booking->guest_id != Auth::id()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized access to this booking'
            ], 403);
        }
        
        try {
            DB::transaction(function() use ($booking) {
                // Update booking status
                $booking->status = 'cancelled';
                $booking->save();
                
                //Update property availability
                $property = $booking->property;
                $property->status = 'available';
                $property->save();


                $invoice = Invoice::where('booking_id', $booking->id)->first();
                if ($invoice) {
                    $invoice->delete();
                }
            });
            
           return response()->json([
               'status' => 'success',
               'message' => 'Booking cancelled successfully'
           ]);
        }
        catch (\Exception $e) {
            \Log::error('Failed to cancel booking: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to cancel booking. Please try again later.'
            ], 500);
        }
    }
}