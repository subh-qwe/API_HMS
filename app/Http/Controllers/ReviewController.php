<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\PropertyReview;
use App\Models\bookings;
use App\Models\Properties;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;

class ReviewController extends Controller
{
    /**
     * Store a property review after verifying the user has booked the property
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function reviewProperty(Request $request)
    {
        // Validate request data
        $validatedData = Validator::make($request->all(), [
            'property_id' => 'required|exists:properties,id',
            'booking_id' => 'required|exists:bookings,id',
            'rating' => 'required|integer|min:1|max:5',
            'comment' => 'required|string',
        ]);

        $user = Auth::user();

         
        // Verify booking belongs to the authenticated user
        $booking = bookings::where('id', $validatedData['booking_id'])
            ->where('guest_id', $user->id)
            ->first();

        if (!$booking) {
            return response()->json([
                'success' => false,
                'message' => 'You can only review properties that you have booked.'
            ], 403);
        }

        // Verify booking is for the specified property
        if ($booking->property_id != $validated['property_id']) {
            return response()->json([
                'success' => false,
                'message' => 'The booking is not for the specified property.'
            ], 400);
        }

        // Check if the booking is completed before allowing review
        $currentDate = Carbon::now();

        //lt method is to check the date is less than the checkout date
        if ($currentDate->lt($booking->check_out_date)) {
            return response()->json([
                'success' => false,
                'message' => 'You can only review a property after your stay is complete.'
            ], 400);
        }

         // Check if user has already reviewed this booking.
        $existingReview = PropertyReview::where('booking_id', $validated['booking_id'])
            ->where('guest_id', $user->id)
            ->first();

        if ($existingReview) {
            return response()->json([
                'success' => false,
                'message' => 'You have already reviewed this booking.'
            ], 400);
        }

        // Create the review
        $review = PropertyReview::create([
            'property_id' => $validatedData['property_id'],
            'booking_id' => $validatedData['booking_id'],
            'user_id' => $user->id,
            'rating' => $validatedData['rating'],
            'comment' => $validatedData['comment'],
       

        ]);


    }

    /**
     * Update property average rating
     *
     * @param int $propertyId
     * @return void
     */
    private function updatePropertyRating($propertyId)
    {
        // Calculate new average rating
        $avgRating = PropertyReview::where('property_id', $propertyId)->avg('rating');
        
        // Update property's rating if you have rating field in properties table
        $property = Properties::find($propertyId);
        if ($property) {
            // Assuming you have an average_rating column in the properties table
            // If not, you may need to adjust this part
            $property->average_rating = round($avgRating, 1);
            $property->save();
        }
    }
}