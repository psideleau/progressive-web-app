/**
 * Created by paul_sideleau on 1/2/17.
 */
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

//webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
    'mailto:paulsideleau@gmail.com',
    'BP6340KYUI_vlqmvCsxIdQIhN-yWEZuJYdYlRfAMwqijFv4DO5B7Eqcnwuy_HRGvbmu2GVW80NCZmpgRVbidaMM',
    'RwhQEnJ6u2WhcuKyGPLHvWJ6md6kN0jBQDZMxgy4ef8'
);

// This is the same output of calling JSON.stringify on a PushSubscription
const pushSubscription = {
    endpoint: 'https://fcm.googleapis.com/fcm/send/crV61jgsNBY:APA91bEdPY7uQdWVzPjdU2wor5CrlPiOmkZai5XcD1pvUpDFsgs3uvR0LA2pjpLjsoN__j5-ch1tyIYoWYggEL-wBOVVr8JsdoF_yuh5jOp-7XeyucHE_XHA3-wPXi1r9o-W4pZU-x9s',
    keys: {
        auth: '1Pc3Dhp7hTy_1hPbAYY1dA==',
        p256dh: 'BNDfSPDWTn9cv08ca-ea4qm0IuYEW_pCorhhCABqEhBMV6HPgLqajtXfqKKv1VRQWo_0F1dmR8E2Y9AY1629o34='
    }
};

webpush.sendNotification(pushSubscription, 'Your Push Payload Text');