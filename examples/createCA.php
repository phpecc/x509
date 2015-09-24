<?php

require "../vendor/autoload.php";


use Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\X509\Serializer\Signature\DerSignatureSerializer;

$curveName = 'secp256k1';
$hasherName = 'sha512';

$math = \Mdanter\Ecc\EccFactory::getAdapter();
$f = new \Mdanter\X509\Factory();
$domain = $f->getDomain($math, $curveName, $hasherName);

$issuerDetails = [
    "commonName" => "test ca"
];
$issuerSubject = new \Mdanter\X509\Certificates\CertificateSubject($issuerDetails);

$ca = $f->getCA($math, $domain, $issuerSubject);

$serializer = new \Mdanter\X509\Serializer\Certificates\CertificateSerializer(new CertificateSubjectSerializer(), new DerPublicKeySerializer(), new DerSignatureSerializer());
