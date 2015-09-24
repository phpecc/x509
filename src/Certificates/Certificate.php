<?php

namespace Mdanter\X509\Certificates;

use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\X509\SignatureAlgorithm;

class Certificate
{
    /**
     * @var CertificateInfo
     */
    private $info;

    /**
     * @var SignatureAlgorithm
     */
    private $sigAlg;

    /**
     * @var SignatureInterface
     */
    private $signature;

    /**
     * @param CertificateInfo $info
     * @param SignatureAlgorithm $sigAlg
     * @param SignatureInterface $signature
     */
    public function __construct(
        CertificateInfo $info,
        SignatureAlgorithm $sigAlg,
        SignatureInterface $signature
    ) {
        $this->info = $info;
        $this->sigAlg = $sigAlg;
        $this->signature = $signature;
    }

    /**
     * @return CertificateInfo
     */
    public function getInfo()
    {
        return $this->info;
    }

    /**
     * @return SignatureAlgorithm
     */
    public function getSigAlgorithm()
    {
        return $this->sigAlg;
    }

    /**
     * @return SignatureInterface
     */
    public function getSignature()
    {
        return $this->signature;
    }
}
