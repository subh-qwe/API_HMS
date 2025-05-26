<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use App\Models\Properties;
use App\Models\UserRegistration;

class PropertyApprovedMail extends Mailable
{
    use Queueable, SerializesModels;

    public $property;
    public $host;
    public $status;

    /**
     * Create a new message instance.
     *
     * @return void
     */
    public function __construct($propertyId,$hostId)
    {
        $this->property = Properties::with('amenities')->find($propertyId);
        $this->host =  UserRegistration::find($hostId);
        $this->status = $this->property->status;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        return $this->subject('Congratulation your property has listed live in our platform !')
                    ->view('emails.property_approved')
                        ->with([
                            'property' => $this->property,
                            'host' => $this->host,
                            'status' => $this->status                 
                        ]);
    }
}
