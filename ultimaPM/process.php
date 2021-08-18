<?php

require 'vendor/autoload.php';

use AmoCRM\Exceptions\AmoCRMApiException;
use AmoCRM\Models\AccountModel;
use AmoCRM\Models\ContactModel;
use AmoCRM\Models\CustomFieldsValues\ValueCollections\MultitextCustomFieldValueCollection;
use AmoCRM\Models\CustomFieldsValues\ValueCollections\TextCustomFieldValueCollection;
use AmoCRM\Models\CustomFieldsValues\MultitextCustomFieldValuesModel;
use AmoCRM\Models\CustomFieldsValues\ValueModels\MultitextCustomFieldValueModel;
use AmoCRM\Models\CustomFieldsValues\ValueModels\TextCustomFieldValueModel;
use AmoCRM\Models\CustomFieldsValues\TextCustomFieldValuesModel;
use AmoCRM\Exceptions\AmoCRMApiNoContentException;
use AmoCRM\Collections\LinksCollection;
use AmoCRM\Models\LeadModel;
use AmoCRM\Collections\CustomFieldsValuesCollection;
use AmoCRM\Filters\ContactsFilter;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Token\AccessToken;

Sentry\init(['dsn' => 'https://842fbeda697b4c0692e4e2ea03128a23@o951626.ingest.sentry.io/5900600' ]);

try {
    $name = $_REQUEST['name'];
    $tel = '+' . preg_replace('/\D/', '', $_REQUEST['tel']);
    $email = $_REQUEST['email'];

    if (!$name || !$tel || !$email) {
        return http_response_code(500);
    }

    GetResponseService::save($name, $email, $tel);

    $amoCrmService = new AmoCrmService();

    $amoCrmService->save($name, $email, $tel);
} catch (Exception $e) {
    return http_response_code(500);
}

class GetResponseService
{
    public static function save($name, $email, $tel)
    {
        $client = new GuzzleHttp\Client(['http_errors' => false]);

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        $response = $client->request(
            'POST',
            'https://api.getresponse.com/v3/contacts',
            [
                'headers' => [
                    'X-Auth-Token' => 'api-key yl9qr7p5o38hmds6wjdsemn305fvcmle',
                    'Content-Type' => 'application/json'
                ],
                'json' => [
                    'name' => $name,
                    'email' => $email,
                    'dayOfCycle' => '0',
                    'campaign' => [
                        'campaignId' => '5EYHl'
                    ],
                    'customFieldValues' => [
                        [
                            'customFieldId' => 'pcfXV2',
                            'value' => [$tel]
                        ]
                    ],
                    'ipAddress' => $ip
                ]
            ]
        );

        $statusCode = $response->getStatusCode();

        if ($statusCode >= 400) {
            throw new Exception(json_encode($response->getBody()->getContents()));
        }
    }
}

class AmoCrmService
{
    private $client;

    public function __construct()
    {
        $clientSecret = '1YPHGQALiHgR0oRLVmlouKq2agtzZlTLWmhjdVKgDOTNk70oDmFGTmqOhWOOiRcS';
        $clientId = '6c3077bf-578c-415a-bc8e-6e41d80ade12';
        $redirectUri = 'https://cursos.ultima.school/amocrm/callback';
        $code = 'def50200806365af0782c8b033f66400e547e9e8316c857cbd232439102a10835729b1040639a815a55da31b88226f161196e0f360c3abf19a4fa410690a972cb490b60c584ff43b99baee3435b7e3bb02f0c149e614a4edf6028981ca4298b8c81020d8d82805c21ad7a31a64de252032eeb9380904ff3acce12300772d5708ab84e7dfe25acae369dee02131d9aed093590bdfaa899e2ddd623c57a826fadd9b74b2b533f9ca97b4e627cfe942cef7c731ab2d458a90406fde80421080235069b4d42d86e5b0c6fc32728372948c7c983eb4ebfbf558e2937d9caa305e9a9c80937d0280eaa07b59a242324a3488179a908e3f6f7ebe25c7567fa212f54fa29824f249c3331b6da78edb0f54bda61e256d860588686ae1ccead839567dfe8eb7bb1ab8a54c44292d2f532277c12e85f4030e1622a2a74054140174b306807c8d037e0533643c99d789dd9ef0d9d4927c33439bb84459f5e21ee1749406ad338e5e159dbf8feb157ec4e9b37f06722006b56e9630954528f33a245b4bf25128fbe1520a3ffe427966f5bd4c1674950c1daa870b95be899deab616e701ecb230828d78dfa0f194d087cfd5f0d5749f487f63c5b9c3f2855f1dec379866237460495395f9ea94c11d5e4690703a19a46e0fba902f83eef53f';
        $baseDomain = 'ultimaschool.amocrm.com';

        $apiClient = new \AmoCRM\Client\AmoCRMApiClient($clientId, $clientSecret, $redirectUri);
        $apiClient->setAccountBaseDomain($baseDomain);

        $accessToken = file_get_contents('amocrm.txt');

        if ($accessToken) {
            $accessToken = json_decode($accessToken, true);

            $accessToken = new AccessToken([
                'access_token' => $accessToken['accessToken'],
                'refresh_token' => $accessToken['refreshToken'],
                'expires' => $accessToken['expires'],
                'baseDomain' => $accessToken['baseDomain'],
            ]);
        } else {
            $accessToken = $apiClient->getOAuthClient()->getAccessTokenByCode($code);

            file_put_contents('amocrm.txt', json_encode([
                'accessToken' => $accessToken->getToken(),
                'refreshToken' => $accessToken->getRefreshToken(),
                'expires' => $accessToken->getExpires(),
                'baseDomain' => $baseDomain
            ]));
        }

        $apiClient->setAccessToken($accessToken)
                ->setAccountBaseDomain('ultimaschool.amocrm.com')
                ->onAccessTokenRefresh(
                    function (AccessTokenInterface $accessToken, string $baseDomain) {
                        file_put_contents('amocrm.txt', json_encode([
                            'accessToken' => $accessToken->getToken(),
                            'refreshToken' => $accessToken->getRefreshToken(),
                            'expires' => $accessToken->getExpires(),
                            'baseDomain' => $baseDomain,
                        ]));
                    }
                );

        $this->client = $apiClient;
    }

    public function save($name, $email, $tel)
    {
        $contact = $this->storeOrGetContact($name, $email, $tel);

        $utms = [];
        $ref = $_SERVER['HTTP_REFERER'];
        $url = parse_url($ref);

        if (isset($url['query'])) {
            parse_str($url['query'], $utms);
        }

        $lead = $this->createLead('Product Management', [
            1414839 => isset($utms['utm_medium']) ? $utms['utm_medium'] : '',
            1414841 => isset($utms['utm_term']) ? $utms['utm_term'] : '',
            1414843 => isset($utms['utm_campaign']) ? $utms['utm_campaign'] : '',
            1414845 => isset($utms['utm_content']) ? $utms['utm_content'] : '',
            1414849 => isset($utms['utm_name']) ? $utms['utm_name'] : '',
            1414851 => isset($utms['utm_source']) ? $utms['utm_source'] : '',
            1499105 => $ref,
        ]);

        $links = new LinksCollection();

        $links->add($contact);
            
        $this->client->leads()->link($lead, $links);
    }

    private function storeOrGetContact($name, $email, $tel)
    {
        $filter = new ContactsFilter();
        $filter->setQuery($email);

        try {
            $contacts = $this->client->contacts()->get($filter);
        } catch (AmoCRMApiNoContentException $e) {
            $contacts = null;
        }

        if (isset($contacts[0])) {
            return $contacts[0];
        } else {
            $contact = new ContactModel();
            $contact->setName($name);

            $contactsCustomFieldsValues = new CustomFieldsValuesCollection();

            $telField = (new TextCustomFieldValuesModel())->setFieldCode('PHONE');
            $telField->setValues(
                (new TextCustomFieldValueCollection())
                    ->add(
                        (new TextCustomFieldValueModel())
                            ->setValue($tel)
                    )
            );
            $contactsCustomFieldsValues->add($telField);

            $emailField = (new TextCustomFieldValuesModel())->setFieldCode('EMAIL');
            $emailField->setValues(
                (new TextCustomFieldValueCollection())
                    ->add(
                        (new TextCustomFieldValueModel())
                            ->setValue($email)
                    )
            );
            $contactsCustomFieldsValues->add($emailField);

            $contact->setCustomFieldsValues($contactsCustomFieldsValues);

            $contactModel = $this->client->contacts()->addOne($contact);

            return $contactModel;
        }
    }

    private function createLead($name, $fields)
    {
        $lead = new LeadModel();

        $leadCustomFieldsValues = new CustomFieldsValuesCollection();

        foreach ($fields as $key => $value) {
            $textCustomFieldValueModel = new TextCustomFieldValuesModel();
            $textCustomFieldValueModel->setFieldId($key);
            $textCustomFieldValueModel->setValues(
                (new TextCustomFieldValueCollection())
                    ->add((new TextCustomFieldValueModel())->setValue($value))
            );
            $leadCustomFieldsValues->add($textCustomFieldValueModel);
        }

        $lead->setCustomFieldsValues($leadCustomFieldsValues);

        $lead->setName($name);

        $lead->setPipelineId(4490092)->setStatusId(41515582);

        $lead = $this->client->leads()->addOne($lead);

        return $lead;
    }
}
