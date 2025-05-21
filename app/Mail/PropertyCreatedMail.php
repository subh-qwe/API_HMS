<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use App\Models\Properties;
use App\Models\UserRegistration;

class PropertyCreatedMail extends Mailable
{
    use Queueable, SerializesModels;

    public $property;
    public $hostid;

    public function __construct(Properties $property, UserRegistration $hostid)
    {
        $this->property = $property;
        $this->hostid = $hostid;
    }

    /**
     * Build the message and sent the message with the property and host details.
     *
     * @return $this
     */
    public function build()
    {
        return $this->subject('Your Property Has Been Created Successfully')
                    ->view('emails.property_created')
                    ->with([
                        'property' => $this->property,
                        'host' => $this->hostid,
                    ]);
    }
}

