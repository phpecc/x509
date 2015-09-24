<?php

namespace Mdanter\X509\Extensions\Extension;

use FG\ASN1\Universal\ObjectIdentifier;
use Mdanter\X509\Extensions\MultiValuedExtension;

class ExtendedKeyUsage extends MultiValuedExtension
{
    public function __construct($critical)
    {
        parent::__construct($critical);
    }

    public function addKeyPurpose()
    {

    }
}
