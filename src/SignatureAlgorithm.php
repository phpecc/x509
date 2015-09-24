<?php

namespace Mdanter\X509;

class SignatureAlgorithm
{
    /**
     * @var Hasher
     */
    private $hasher;

    /**
     * @param Hasher $hasher
     */
    public function __construct(Hasher $hasher)
    {
        $this->hasher = $hasher;
    }

    /**
     * @return string
     */
    public function algorithm()
    {
        return "ecdsa+" . $this->hasher->getAlgo();
    }
}
