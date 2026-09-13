<?php

namespace Lineage\Exceptions;

use Exception;

class KeypairNotDecryptedException extends Exception
{
    // 400 Bad Request. Not Illuminate\Http\Response::HTTP_BAD_REQUEST:
    // illuminate/http isn't (and never has been) a composer.json dependency
    // of this package, so referencing it fatals with "class not found" the
    // moment this exception is actually thrown.
    protected $code = 400;
    protected $message = 'Could not decrypt keypair';
}
