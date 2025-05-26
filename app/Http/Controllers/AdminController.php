<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Exception;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use App\Mail\PropertyApprovedMail;
use App\Mail\PropertyRejectMail;
use App\Models\UserRegistration;
use App\Models\Properties;
use App\Models\bookings;


class AdminController extends Controller
{
   
    public function adminActions()
    {           
        return response()->json([
            'status' => 'success',
            'message' => 'This is admin dashboard'
        ], 200);
    }

    public function getUnavailableProperties()
    {
        try
        {
            $unavailableProperties = Properties::where('status', 'unavailable')
                                    ->with([
                                        'images', 'amenities', 
                                        'host:id,name,email,phone_number,profile_image'])
                                    ->paginate(10);

            return response()->json([
                'status' => 'success',
                'message' => 'Successfully got unavailable properties',
                'data' => $unavailableProperties
            ], 200);
        } 
        catch (\Exception $e){
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to get unavailable properties',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getAllStats(){
        try{
            $totalProperties = Properties::count();
            $totalUsers = UserRegistration::whereIn('role',['guest','host'])->count();
            $totalBookings = Bookings::count();

            return response()->json([
                'status' => 'success',
                'message' => 'Successfully got all stats',
                'data' => [
                    'total_properties' => $totalProperties,
                    'total_users' => $totalUsers,
                    'total_bookings' => $totalBookings
                ]
            ], 200);
        }
        catch(\Exception $e){
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to get the stats',
                'error' => $e->getMessage()
            ], 500);
        }
    }
 
    public function UpdatePropertyStatus(Request $request)
    {
        $status = $request->input('status');
        $propertyId = $request->input('property_id');
        
        try
        {
            $property = Properties::with('host')->findOrFail($propertyId);

            $res=Properties::UpdatePropertyStatus($status, $propertyId);


            if($res && $property->host)
            {
                $hostEmail = $property->host->email;

            try {
                Mail::to($hostEmail)->send(new PropertyApprovedMail($propertyId, $property->host_id));

                 Log::info('Property status update email sent successfully');
            } 
            catch (\Exception $e) {
                // Log error but don't fail the request
                \Log::error('Failed to send booking invoice email: ' . $e->getMessage());
                 return response()->json(['error' => 'Failed to send email'], 500);                              
            }

            }

            return response()->json([
                'status' => 'success',
                'message' => "Successfully updated property status"
            ], 200);
        } 
        catch(Exception $e){
           return response()->json([
                'status' => 'error',
                'message' => 'Failed to update property status',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function rejectProperties(Request $request)
    {
        $propertyDetails = $request->input('property_id');

       
    try         
    {             
        $propertyHost = Properties::with('host')->where('id', $propertyDetails)->first();              

            // Check if property exists
            if (!$propertyHost) {
                \Log::error('Property not found with ID: ' . $propertyDetails);
                return response()->json(['error' => 'Property not found'], 404);
            }

            // Check if host relationship exists
            if (!$propertyHost->host) {
                \Log::error('Host not found for property ID: ' . $propertyDetails);
                return response()->json(['error' => 'Host not found for this property'], 404);
            }

            // Check if host email exists
            if (!$propertyHost->host->email) {
                \Log::error('Host email not found for property ID: ' . $propertyDetails . ', Host ID: ' . $propertyHost->host_id);
                return response()->json(['error' => 'Host email not found'], 400);
            }

            \Log::info('Sending rejection email to: ' . $propertyHost->host->email);
            
            Mail::to($propertyHost->host->email)->send(new PropertyRejectMail($propertyHost));
            
            return response()->json(['message' => 'Rejection email sent successfully'],200);
        }         
        catch(Exception $e)         
        {              
            \Log::error('Failed to send property rejection email: ' . $e->getMessage());
            return response()->json(['error' => 'Failed to send email'], 500);
        }     
    }

    public function getBookings(){
        try{
            $bookings = bookings::paginate(10);
            // dd($bookings);
            return response()->json([
                'status' => 'success',
                'message' => 'Successfully got all bookings',
                'data' => $bookings
            ], 200);
        }
        catch(\Exception $e){
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to get booking details',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function getAllUsers(){
        try{
            $users = UserRegistration::whereIn('role',['guest','host'])->paginate(10);

            return response()->json([
                'status' => 'success',
                'message' => 'Successfully got all users',
                'data' => $users
            ], 200);
        }
        catch(\Exception $e){
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to get all users',
                'error' => $e->getMessage()
            ], 500);
        }
    }


    

    public function logout()
    {
        try
        {
            Auth::logout();
            return response()->json([
                'status' => 'success',
                'message' => 'Successfully logged out'
            ], 200);
        } 
        catch (\Exception $e){
            return response()->json([
                'status' => 'error',
                'message' => 'Logout failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}
