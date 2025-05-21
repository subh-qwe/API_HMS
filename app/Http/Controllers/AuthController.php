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
use App\Services\CloudinaryService;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{

    protected $cloudinary;

    public function __construct(CloudinaryService $cloudinary)
    {
        $this->cloudinary = $cloudinary;
    }

    // Public function to register the user
    public function signup(Request $request)
{
    // Validate request data
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'email' => 'required|email|unique:users,email',
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
    
     // This function handles user registration and send the verification email
    public function verifyOtp(Request $request){
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,email',
            'otp' => 'required|numeric'
        ]);
        
        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }
         $user = User::where('email', $request->user_id)->first();
        
        // Check if user exists
        if ($user->otp != $request->otp) {
            return response()->json(['error' => 'Invalid OTP'], 400);
        }
        
        // here i am using the comment 
        $user->otp = null; 
        $user->email_verified_at = \Carbon\Carbon::now(); 
        $user->save();
        $rrt=0; // this is og no use 
        
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
    
    // This function is use to resend the OTP to the user email
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

    // Public Function to login the user
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'email|required',
            'password' => 'required'
        ], [
            'email.email' => 'Enter a valid Email',
            'email.required' => 'Email is required field',
            'password.required' => 'Password is required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => "Invalid Credentials",
                'errors' => $validator->errors()
            ], 422);
        }

        // First, check if user exists with the provided email
        $user = UserRegistration::where('email', $request->email)->first();
        
        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Credentials'
            ], 401);
        }


        // Get credentials for attempt
        $credentials = $request->only(['email', 'password']);

        // Attempt to authenticate
        if (!$token = Auth::attempt($credentials)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Credentials'
            ], 401);
        }

        // Return token if authentication successful
        return $this->respondWithToken($token);
    }

    /**
     * Get the token array structure.
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'status' => 'success',
            'message' => 'Login Successfully!',
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60 // in seconds
        ], 200);
    }

    /**
     * Refresh a token.
     */
    public function refresh()
    {
        return $this->respondWithToken(Auth::refresh());
    }

    
    // Public function to logout the user 
    public function logout()
    {
        Auth::logout();

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out'
        ], 200);
    }
   
}