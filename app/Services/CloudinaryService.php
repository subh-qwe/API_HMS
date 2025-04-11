<?php

namespace App\Services;

use Cloudinary\Cloudinary;
use Illuminate\Http\UploadedFile;

class CloudinaryService
{
    protected $cloudinary;

    public function __construct(Cloudinary $cloudinary)
    {
        $this->cloudinary = $cloudinary;
    }

    public function uploadFile(UploadedFile $file, string $folder = null)
    {
        $options = [
            'resource_type' => 'auto',
            'folder' => $folder
        ];

        return $this->cloudinary->uploadApi()->upload(
            $file->getRealPath(),
            $options
        );
    }

    public function deleteFile(string $publicId)
    {
        return $this->cloudinary->uploadApi()->destroy($publicId);
    }
}