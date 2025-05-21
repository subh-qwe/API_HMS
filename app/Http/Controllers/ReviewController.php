<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\PropertyReview;
use App\Models\bookings;
use App\Models\Properties;
use App\Models\PropertyRating;
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

        if ($validatedData->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validatedData->errors()
            ], 422);
        }

        $validated = $validatedData->validated();
        
        $user = Auth::user();

        // Verify booking belongs to the authenticated user
        $booking = bookings::where('id', $validated['booking_id'])
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

        // Check if the booking status is completed before allowing review
        if ($booking->status != 'completed') {
            return response()->json([
                'success' => false,
                'message' => 'You can only review once the booking is completed and confirmed.'
            ], 400);
        }
        

         // Checking if user has already reviewed this booking.
        $existingReview = PropertyReview::where('booking_id', $validated['booking_id'])
            ->where('guest_id', $user->id)
            ->first();

        if ($existingReview) {
            return response()->json([
                'success' => false,
                'message' => 'You have already reviewed this booking.'
            ], 400);
        }

        
        DB::beginTransaction();
        
        try {
            // Create new review
            $review = new PropertyReview();
            $review->booking_id = $validated['booking_id'];
            $review->property_id = $validated['property_id'];
            $review->guest_id = $user->id;
            $review->rating = $validated['rating'];
            $review->comment = $validated['comment'];
            $review->save();

            // Update property rating
            $this->updatePropertyRating($validated['property_id']);
            
            // Commit transaction
            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Review submitted successfully.',
                
            ], 201);
            
        } 
        catch (\Exception $e) {
            // Rollback transaction on error
            DB::rollBack();
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to submit review. Please try again.',
                'error' => $e->getMessage()
            ], 500);
        }

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
        $avgRating = PropertyReview::where('property_id', $propertyId)->avg('rating') ?: 0;
        $reviewCount = PropertyReview::where('property_id', $propertyId)->count();

        
        $avgRating = round($avgRating, 2);

         
        //update the property rating if not then create
         DB::transaction(function() use ($propertyId, $avgRating, $reviewCount) {
            //check if the property rating exists
            $rating = PropertyRating::where('property_id', $propertyId)->first();
            
            if ($rating) {
                $rating->update([
                    'average_rating' => $avgRating,
                    'review_count' => $reviewCount,
                    'updated_at' => Carbon::now()
                ]);
            } 
            //create the property rating if not exists
            else {
                PropertyRating::create([
                    'property_id' => $propertyId,
                    'average_rating' => $avgRating,
                    'review_count' => $reviewCount,
                    'updated_at' => Carbon::now()
                ]);
            }
        });
    
    }
}