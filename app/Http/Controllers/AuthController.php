<?php
namespace App\Http\Controllers;
use App\Models\User;
use App\Models\UserRegistration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use App\Mail\VerificationEmail;
use App\Mail\WelcomeEmail;
use Carbon\Carbon;
use DB;
use App\Services\CloudinaryService;

class AuthController extends Controller
{

    protected $cloudinary;

    public function __construct(CloudinaryService $cloudinary)
    {
        $this->cloudinary = $cloudinary;
    }
    public function signup(Request $request)
{
    // Validate request data
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|email|unique:user_registrations,email',
        'password' => 'required|min:6',
        'phone_number' => 'required|string',
        'profile_image' => 'nullable|image|max:2048',
    ]);

    // Check if validation fails
    if ($validator->fails()) {
        return response()->json([
            'success' => false,
            'errors' => $validator->errors()
        ], 422);
    }
    
    // Generate a 6-digit OTP
    $otp = mt_rand(100000, 999999);
    
    try {
        // Initialize profile image URL
        $profileImageUrl = null;
        
        // Process image upload if provided
        if ($request->hasFile('profile_image')) {
            try {
                $file = $request->file('profile_image');
                $result = $this->cloudinary->uploadFile($file, 'user_profiles');
                $profileImageUrl = $result['secure_url'];
            } catch (\Exception $e) {
                \Log::error('Failed to upload image to Cloudinary: ' . $e->getMessage());
                // Continue with registration but without profile image
            }
        }
        
        // Create user
        $user = UserRegistration::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'phone_number' => $request->phone_number,
            'profile_image' => $profileImageUrl ?? null,
            'role' => "guest",
            'otp' => $otp 
        ]);
        
        // Prepare email data
        $mailData = [
            'name' => $user->name,
            'otp' => $otp
        ];
        
        // Send verification email
        try {
            Mail::mailer('smtp')->to($user->email)->send(new VerificationEmail($mailData));
            
            return response()->json([
                'success' => true,
                'message' => 'Registration successful! Please check your email for OTP verification.',
                'user_id' => $user->id
            ], 201);
            
        } catch (\Exception $e) {
            \Log::error('Failed to send verification email: ' . $e->getMessage());
            \Log::error('Exception trace: ' . $e->getTraceAsString());
            
            // Registration succeeded but email failed
            return response()->json([
                'success' => true,
                'message' => 'Registration successful but verification email could not be sent. Please contact support.',
                'user_id' => $user->id,
                'otp' => $otp // Only include this in development environment
            ], 201);
        }
        
    } catch (\Exception $e) {
        \Log::error('User registration failed: ' . $e->getMessage());
        \Log::error('Exception trace: ' . $e->getTraceAsString());
        
        return response()->json([
            'success' => false,
            'message' => 'Registration failed. Please try again later.',
            'error' => config('app.debug') ? $e->getMessage() : 'Internal server error'
        ], 500);
    }
}
    
    // Verify OTP
    public function verifyOtp(Request $request){
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id',
            'otp' => 'required|numeric'
        ]);
        
        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }
        
        $user = User::find($request->user_id);
        
        if ($user->otp != $request->otp) {
            return response()->json(['error' => 'Invalid OTP'], 400);
        }
        
        $user->otp = null; 
        $user->email_verified_at = \Carbon\Carbon::now(); 
        $user->save();
        
        // Send welcome email
        $mailData = [
            'name' => $user->name
        ];
        
        try {
            Mail::to($user->email)->send(new WelcomeEmail($mailData));
        } catch (\Exception $e) {
            // Log the error but continue with the verification process
            \Log::error('Failed to send welcome email: ' . $e->getMessage());
        }
        
        return response()->json(['message' => 'Email verified successfully! You can now log in.']);
    }
    
    public function resendOtp(Request $request){
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id'
        ]);
        
        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }
        
        $user = User::find($request->user_id);
        
        // Generate a new 6-digit OTP
        $otp = mt_rand(100000, 999999);
        $user->otp = $otp;
        $user->save();
        
        // Send verification email with new OTP
        $mailData = [
            'name' => $user->name,
            'otp' => $otp
        ];
        
        try {
            Mail::to($user->email)->send(new VerificationEmail($mailData));
            
            return response()->json([
                'message' => 'New OTP sent to your email.'
            ]);
            
        } catch (\Exception $e) {
            // Log the error
            \Log::error('Failed to send OTP email: ' . $e->getMessage());
            
            return response()->json([
                'error' => 'Could not send OTP email. Please try again.'
            ], 500);
        }
    }
}