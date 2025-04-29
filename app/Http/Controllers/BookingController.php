<?php

namespace App\Http\Controllers;


use App\Models\bookings;
use App\Models\Properties;
use Auth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class BookingController extends Controller
{
    //
    // Function to book a property
    public function bookProperty(Request $request)
    {
        // Validate request data
        $validator = validator::make($request->all(), [
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
        
        // Check for availability (you might want to implement a more robust availability check)
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
        $total_price = $days * $property->price_per_night;
        
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
       
}
