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
                    'customFieldValues' => [
                        [
                            'customFieldId' => 'pcfXV2',
                            'value' => [$tel]
                        ]
                    ],
                    'campaign' => [
                        'campaignId' => '5EYHl'
                    ],
                    'ipAddress' => $ip
                ]
            ]
        );

        $statusCode = $response->getStatusCode();

        if ($statusCode !== 202) {
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
        $code = 'def502000a2efe6ae58450025b9c21893044a98de901e520d970827aad4f7d930a539307c99f03f45d47ecafe4fb3aa78443d3371968467fc76702e0939a148a549e6330d5b7b0d01d099985e4391c63631dfe1804e0316e99004c77c314a2a3824a2308e6acd8a477ff4ace199fa64378f1280feea400443fec658d93cf4d5a98e0ba8363c854b3e65fb7c683e86fd85d1fdfa7f46876df22967eb4a26049b682fd0fb3a12d4079db64f6880dec5ca5395f821836b3bfc0f1dfd505152ceb854586a26d5fb222fca17332efdeaee8a2be2ccd91dd44353a073a87717e299f06c5f6cefb0cc06512ba9d57a2989bab13cdb0af2b3abcf8426b0ac44829b50270ab1340784d0f9ec9c1db9990aeaf786d69ea036ad814b94936fa1bf5cd30b002dc3d39cf00c442831ff34e09a07877faf199124cac5d943bebdda14bcf24bbcd0aab078aab1ea5e7d6ee552bcbb794019307331d1fbc75e20fd4942f81ab53e1b40ecd226a7d2ec5f4f1d78101a43ad35b8d218881fef59caf38b8ec2f7181cbe9b9e157216517741532fc99733037d32ab1c6eb46c358868bdd1faa8337684258c5dbe5b336b70e0f94330baa260058b568697560d2964c49ca3a88359578ba4cf6a940afe15a40a943d67caff6b20f95fc2506d9822117';
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
