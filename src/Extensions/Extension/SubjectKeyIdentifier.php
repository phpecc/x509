<?php

namespace Mdanter\X509\Extensions\Extension;

use Mdanter\X509\Extensions\StringExtension;

class SubjectKeyIdentifier extends StringExtension
{
    /**
     * @var string
     */
    private $identifier;

    /**
     * @param bool|null $critical
     */
    public function __construct($critical)
    {
        parent::__construct($critical);
    }

    /**
     * @param string $identifier
     */
    public function addIdentifier($identifier)
    {
        $this->value = $identifier;
    }

    /**
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }
}
