<?php

namespace Lineage\Exceptions;

use Exception;

/**
 * Thrown by the trade/2-way-payment surface (createTradeRequest,
 * getPendingTransactions, acceptPendingTransaction/rejectPendingTransaction),
 * which is deferred until the /v1 2-way payment endpoints land.
 */
class NotImplemented extends Exception
{
    protected $code = 501;
    protected $message = '2-way payments deferred';
}
