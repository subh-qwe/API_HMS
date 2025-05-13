<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\Properties;
use App\Services\CloudinaryService;
use App\Models\PropertyImages;
use App\Models\Amenity;

class PropertyController extends Controller
{
    protected $cloudinaryService;

    public function __construct(CloudinaryService $cloudinaryService)
    {
        $this->cloudinaryService = $cloudinaryService;
    }

    
    public function store(Request $request)
    {
        
        // Validate the input
        $validator = Validator::make($request->all(), [
            'host_id' => 'required|integer|exists:users,id',
            'title' => 'required|string|max:100',
            'description' => 'nullable|string',
            'property_type' => 'required|in:apartment,house,villa,condo,cabin',
            'address' => 'required|string|max:255',
            'city' => 'required|string|max:100',
            'state' => 'required|string|max:100',
            'zip_code' => 'required|string|max:20',
            'latitude' => 'nullable|numeric',
            'longitude' => 'nullable|numeric',
            'bedrooms' => 'required|integer|min:0',
            'bathrooms' => 'required|integer|min:0',
            'max_guests' => 'required|integer|min:1',
            'price_per_night' => 'required|numeric|min:0',
            'cleaning_fee' => 'nullable|numeric|min:0',
            'service_fee' => 'nullable|numeric|min:0',
            'status' => 'required|in:available,unavailable,maintenance',

            //Validation for images
            //required_with:images: Ensures an image is provided if the images array exists.
            // 'images.*.image' => 'required_with:images|url|image|mimes:jpeg,jpg,png,gif|max:2048', if you want to validate the image URL
            'images' => 'required|array|min:1',
            'images.*.image' => 'required|file|image|mimes:jpeg,jpg,png,gif|max:2048',
            'images.*.is_featured' => 'nullable|boolean',
            'images.*.caption' => 'nullable|string|max:250',
            


            //Validation for amenities
            'amenities' => 'required|array|min:1',
            'amenities.*' => 'integer|exists:amenities,id',
        ], 
        [
            'host_id.required' => 'The host ID is mandatory.',
            'host_id.integer' => 'The host ID must be a valid number.',
            'host_id.exists' => 'The host ID does not exist.',
            'title.required' => 'Please provide a title for the property.',
            'title.string' => 'The title must be text.',
            'title.max' => 'The title cannot exceed 100 characters.',
            'description.string' => 'The description must be text.',
            'property_type.required' => 'Please specify the type of property.',
            'property_type.in' => 'The property type must be one of: apartment, house, villa, condo, or cabin.',
            'address.required' => 'The property address is required.',
            'address.string' => 'The address must be text.',
            'address.max' => 'The address cannot exceed 255 characters.',
            'city.required' => 'Please provide the city name.',
            'city.string' => 'The city must be text.',
            'city.max' => 'The city name cannot exceed 100 characters.',
            'state.required' => 'Please provide the state name.',
            'state.string' => 'The state must be text.',
            'state.max' => 'The state name cannot exceed 100 characters.',
            'zip_code.required' => 'The zip code is required.',
            'zip_code.string' => 'The zip code must be text.',
            'zip_code.max' => 'The zip code cannot exceed 20 characters.',

            'latitude.numeric' => 'Latitude must be a number.',
            'longitude.numeric' => 'Longitude must be a number.',
            

            'bedrooms.required' => 'Please specify the number of bedrooms.',
            'bedrooms.integer' => 'The number of bedrooms must be a number without decimals.',
            'bedrooms.min' => 'The number of bedrooms cannot be negative.',

            'bathrooms.required' => 'Please specify the number of bathrooms.',
            'bathrooms.integer' => 'The number of bathrooms must be numeric .',
            'bathrooms.min' => 'The number of bathrooms cannot be negative.',

            'max_guests.required' => 'Please specify the maximum number of guests.',
            'max_guests.integer' => 'The maximum number of guests must be a positive whole number.',
            'max_guests.min' => 'The maximum number of guests must be at least 1.',

            'price_per_night.required' => 'Please provide the price per night.',
            'price_per_night.numeric' => 'The price per night must be a valid number.',
            'price_per_night.min' => 'The price per night cannot be negative.',
            'cleaning_fee.numeric' => 'The cleaning fee must be a valid number.',
            'cleaning_fee.min' => 'The cleaning fee cannot be negative.',
            'service_fee.numeric' => 'The service fee must be a valid number.',
            'service_fee.min' => 'The service fee cannot be negative.',
            'status.required' => 'Please specify the property status.',
            'status.in' => 'The status must be one of: available, unavailable, or maintenance.',

            // * in 'images.*.image' is a wildcard that applies the validation rules to the image field of every element in the images
            'images.*.image.required' => 'An image file is required when providing images.',
            'images.*.image.mimes' => 'Each image must be a JPEG, JPG, PNG, or GIF file.',            
            'images.*.image.max' => 'Each image cannot exceed 2MB.',
            'images.*.is_featured.boolean' => 'The featured status must be true or false.',
            'images.*.caption.max' => 'Each image caption cannot exceed 250 characters.',



            'amenities.*.integer' => 'Each amenity ID must be a number.',
            'amenities.required' => 'At least one amenity is required.',
            'amenities.*.exists' => 'One or more amenity IDs are invalid.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            // Start a database transaction
            DB::beginTransaction();

                // Retrieve validated data
                $validated = $validator->validated();

                $uploadedPublicIds = [];

                // Create the property
                $property = Properties::create([
                    'host_id' => $validated['host_id'],
                    'title' => $validated['title'],
                    'description' => $validated['description'] ?? null,
                    'property_type' => $validated['property_type'],
                    'address' => $validated['address'],
                    'city' => $validated['city'],
                    'state' => $validated['state'],
                    'zip_code' => $validated['zip_code'],
                    'latitude' => $validated['latitude'] ?? 0 ,
                    'longitude' => $validated['longitude'] ?? 0,
                    'bedrooms' => $validated['bedrooms'],
                    'bathrooms' => $validated['bathrooms'],
                    'max_guests' => $validated['max_guests'],
                    'price_per_night' => $validated['price_per_night'],
                    'cleaning_fee' => $validated['cleaning_fee'] ?? 0,
                    'service_fee' => $validated['service_fee'] ?? 0,
                    'status' => $validated['status'],
                ]);

                
                
                // Handle images
                if ($request->has('images')) {
                    foreach ($validated['images'] as $imageData) {
                        
                        // dd($imageData);
                        $image = $imageData['image'];
                        $result = $this->cloudinaryService->uploadFile($image, 'property_images');
                        
                        
                        
                        // if (!isset($result['secure_url'])) {
                            //     throw new \Exception('Image upload failed');
                            // }
                            
                            $secureUrl = $result['secure_url'];
                            
                            //using public_id for Deleting images from Cloudinary, Updating or transforming assets, Debugging and auditing.
                            $publicId = $result['public_id'] ?? null;
                            $uploadedPublicIds[] = $publicId;
                            
                            $property->images()->create([
                                'image_path' => $secureUrl,
                                'public_id' => $publicId,
                                'caption' => $imageData['caption'] ?? null,
                                'is_featured' => $imageData['is_featured'] ?? false,
                            ]);
                        }
                    }
                    
                    // Handle amenities
                   if ($request->has('amenities')) 
                   {
                       $property->amenities()->sync($validated['amenities']);
                   }

                // Commit the transaction
                DB::commit();

            // Return success response with the created property and its relationships
            return response()->json([
                'message' => 'Property created successfully',
                'data' => $property->load('images', 'amenities')
            ], 201);
        } 

        catch (\Exception $e) {
            DB::rollBack();
            foreach ($uploadedPublicIds as $publicId) {
                if ($publicId) {
                    $this->cloudinaryService->deleteFile($publicId);
                }
            }

            \Log::error('Property creation failed: ' . $e->getMessage(), ['exception' => $e]);
            return response()->json([
                'message' => 'Failed to create property',
                'error' => 'Database error'. $e->getMessage()
            ], 500);
        }
    }

    public function listProperties()
    {
        try
        {
        $properties = Properties::with('images', 'amenities')->get();
        return response()->json([
            'message' => 'Properties retrieved successfully',
            'data' => $properties
        ], 200);
        }
        catch(\Exception $e){
            \Log::error('Failed to retrieve properties: ' . $e->getMessage());

            return response()->json([
                'message'=> 'Failed to retrieve Properties',
                'error' => $e->getMessage()
            ], 500);

        }
    }

    public function getPropertybyId($id){
       
            $property = Properties::with('images', 'amenities')->find($id);
           
            if(!$property){
                return response()->json([
                    'error' => 'Property not found for the given ID',
                ], 404);
            }
    
            // Return success response
            return response()->json([
                'message' => 'Property retrieved successfully',
                'data' => $property
            ], 200);
        
        $property = Properties::with('images', 'amenities')->find($id);

        if(!$property){
            return response()->json([
                'message' => 'Property not found',
            ], 404);
        }

        return response()->json([
            'message' => 'Property retrieved successfully',
            'data' => $property->load('images', 'amenities')
        ], 200);
    }

    public function updateProperty(Request $request, $id)
    {
        $propertyId = Properties::with('images', 'amenities')->find($id);

        // dd($propertyId);

        if(!$propertyId){
            return response()->json([
                "error" => "Property not found ",
            ], 404);
        }

        $credentials = Validator::make($request->all(), [
            'title' => 'required|string|max:255',
            'description' => 'required|string',
            'property_type' => 'required|in:apartment,house,villa,condo,cabin', 
            'address' => 'required|string|max:250',
            'city' => 'required|string|max:100',
            'state' => 'required|string|max:100',
            'zip_code' => 'required|string|max:20',
            'latitude' => 'nullable|numeric',
            'longitude' => 'nullable|numeric',
            'bedrooms' => 'required|integer|min:1',
            'bathrooms' => 'required|integer|min:1',
            'max_guests' => 'required|integer|min:1',
            'price_per_night' => 'required|numeric|min:0',
            'cleaning_fee' => 'nullable|numeric|min:0',
            'service_fee' => 'nullable|numeric|min:0',
            'status' => 'required|in:available,unavailable,maintenance',

            'images' => 'nullable|array|min:1',
            'images.*.image' => 'required|file|image|mimes:jpeg,jpg,png,gif|max:2048',
            'images.*.is_featured' => 'nullable|boolean',
            'images.*.caption' => 'nullable|string|max:250',

            'amenities' => 'nullable|array',
            'amenities.*' => 'exists:amenities,id',  
      
        ]);

        if ($credentials->fails()) {
            return response()->json([
                'errors' => $credentials->errors(),
            ], 422); 
        }

        try{

            $request = $credentials->validated();

            $property = Properties::update([
                'title' => $request->title,
                'description' => $request->description,
                'property_type' => $request->property_type,
                'address' => $request->address,
                'city' => $request->city,
                'state' => $request->state,
                'zip_code' => $request->zip_code,
                'latitude' => $request->latitude,
                'longitude' => $request->longitude,
                'bedrooms' => $request->bedrooms,
                'bathrooms' => $request->bathrooms,
                'max_guests' => $request->max_guests,
                'price_per_night' => $request->price_per_night,
                'cleaning_fee' => $request->cleaning_fee,
                'service_fee' => $request->service_fee,
                'status' => $request->status,
            ]);

             // Handle images if provided
                if ($request->has('images')) {
                    foreach ($validated['images'] as $imageData) {
                        // If an image ID is provided, we are updating an existing image
                        if (isset($imageData['id'])) {
                            $existingImage = $property->images()->find($imageData['id']);

                            if ($existingImage) {
                                // Delete old image from Cloudinary
                                $this->cloudinaryService->deleteFile($existingImage->public_id);

                                // Upload the new image
                                $imageFile = $imageData['image'];
                                $result = $this->cloudinaryService->uploadFile($imageFile, 'property_images');

                                // Update the image record in the database
                                $existingImage->update([
                                    'image_path' => $result['secure_url'],
                                    'public_id' => $result['public_id'],
                                    'caption' => $imageData['caption'] ?? $existingImage->caption,
                                    'is_featured' => $imageData['is_featured'] ?? $existingImage->is_featured,
                                ]);
                            }
                        } else {
                            // If no ID is provided, create a new image record
                            $imageFile = $imageData['image'];
                            $result = $this->cloudinaryService->uploadFile($imageFile, 'property_images');

                            $property->images()->create([
                                'image_path' => $result['secure_url'],
                                'public_id' => $result['public_id'],
                                'caption' => $imageData['caption'] ?? null,
                                'is_featured' => $imageData['is_featured'] ?? false,
                            ]);
                        }
                    }
                }

                 // Sync amenities: Add new amenities, remove old ones not in the list
                    if ($request->has('amenities')) {
                        // First, sync the amenities to ensure proper association
                        $property->amenities()->sync($validated['amenities']);

                        // Now, let's update any existing amenities. We assume that the `is_featured` status or other properties might need updating
                        foreach ($property->amenities as $amenity) {
                            if (in_array($amenity->id, $validated['amenities'])) {
                                // Assuming you're tracking a custom field like 'is_featured' for amenities
                                $amenity->update([
                                    'is_featured' => $request->has('is_featured') ? $request->is_featured : $amenity->is_featured,
                                ]);
                            }
                        }
                    }
        } 
        
        catch (\Exception $e) {
            // Log the error
            Log::error('Failed to update property', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
    
            return response()->json([
                'error' => 'An error occurred while updating the property.',
                'details' => $e->getMessage(), // Optional: Hide in production
            ], 500);
        }

       
    }

    
    public function deleteProperty($id)
    {
        
        try{
            $property = Properties::with('images', 'amenities')->find($id);

            if(!$property)
            {
                return response()->json([
                'message' => 'Property not found',
                ], 404);
            }

            // Delete related images from Cloudinary
            foreach ($property->images as $image) {
                // Delete the image from Cloudinary using its public_id
                $this->cloudinaryService->deleteFile($image->public_id);
            }

            //Delete image records from the database
            $property->images()->delete();

            //Delete property id and all related records of the property_amenity 
            $property->delete();

        return response()->json([
            'message' => 'Property deleted successfully',
        ], 200);


        }
        catch(\Exception $e){
            \Log::error('Property deletion failed: ' . $e->getMessage(), ['exception' => $e]);

            return response()->json([
                'message' => 'Failed to delete property',
                'error' => 'Database error: ' . $e->getMessage()
            ], 500);
        }
    }
}
        
      



