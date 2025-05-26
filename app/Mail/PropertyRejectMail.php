<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class PropertyRejectMail extends Mailable
{
    use Queueable, SerializesModels;

    public $propertyHost;

    /**
     * Create a new message instance.
     *
     * @return void
     */
    public function __construct($propertyHost)
    {
        $this->propertyHost = $propertyHost;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        return $this->subject('Property Listing Rejected')
                    ->view('emails.property_reject')
                    ->with([
                        'propertyHost' => $this->propertyHost ?? 'No Property',
                    ]);
    }
}