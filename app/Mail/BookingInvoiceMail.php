<?php

namespace App\Mail;

use App\Models\bookings;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class BookingInvoiceMail extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * The booking instance.
     *
     * @var \App\Models\bookings
     */
    public $booking;

    /**
     * The path to the invoice PDF file.
     *
     * @var string|null
     */
    protected $invoicePath;

    /**
     * Create a new message instance.
     *
     * @param \App\Models\bookings $booking
     * @param string|null $invoicePath
     * @return void
     */
    public function __construct(bookings $booking, $invoicePath = null)
    {
        $this->booking = $booking;
        $this->invoicePath = $invoicePath;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        $mail = $this->subject('Your Booking Confirmation #' . $this->booking->id)
                     ->view('emails.booking_invoice');
        
        // Attach the PDF invoice if the path is provided
        if ($this->invoicePath && file_exists($this->invoicePath)) {
            $mail->attach($this->invoicePath, [
                'as' => 'invoice_' . $this->booking->id . '.pdf',
                'mime' => 'application/pdf',
            ]);
        }
        
        return $mail;
    }
}