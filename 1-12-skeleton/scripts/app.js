
(function() {
  'use strict';

  var weatherAPIUrlBase = 'https://publicdata-weather.firebaseio.com/';
  const applicationServerPublicKey = 'BP6340KYUI_vlqmvCsxIdQIhN-yWEZuJYdYlRfAMwqijFv4DO5B7Eqcnwuy_HRGvbmu2GVW80NCZmpgRVbidaMM'
      //'BIZqLVG0Ub75DxT4UTn9Q3WIxx8n_FW8ZJFbktFGBSUfJp5hzbpVjw8UMSW5dgkgt7exCi2trlwnVOxSwIBR-Mc'

   var app = {
    isLoading: true,
    visibleCards: {},
    selectedCities: [],
    spinner: document.querySelector('.loader'),
    cardTemplate: document.querySelector('.cardTemplate'),
    container: document.querySelector('.main'),
    addDialog: document.querySelector('.dialog-container'),
    daysOfWeek: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
  };

    var injectedForecast = {
        key: 'newyork',
        label: 'New York, NY',
        currently: {
            time: 1453489481,
            summary: 'Clear',
            icon: 'partly-cloudy-day',
            temperature: 52.74,
            apparentTemperature: 74.34,
            precipProbability: 0.20,
            humidity: 0.77,
            windBearing: 125,
            windSpeed: 1.52
        },
        daily: {
            data: [
                {icon: 'clear-day', temperatureMax: 55, temperatureMin: 34},
                {icon: 'rain', temperatureMax: 55, temperatureMin: 34},
                {icon: 'snow', temperatureMax: 55, temperatureMin: 34},
                {icon: 'sleet', temperatureMax: 55, temperatureMin: 34},
                {icon: 'fog', temperatureMax: 55, temperatureMin: 34},
                {icon: 'wind', temperatureMax: 55, temperatureMin: 34},
                {icon: 'partly-cloudy-day', temperatureMax: 55, temperatureMin: 34}
            ]
        }
    };

  /*****************************************************************************
   *
   * Event listeners for UI elements
   *
   ****************************************************************************/

  /* Event listener for refresh button */
  document.getElementById('butRefresh').addEventListener('click', function() {
    app.updateForecasts();
  });

  /* Event listener for add new city button */
  document.getElementById('butAdd').addEventListener('click', function() {
    // Open/show the add new city dialog
    app.toggleAddDialog(true);
  });

  /* Event listener for add city button in add city dialog */
  document.getElementById('butAddCity').addEventListener('click', function() {
    var select = document.getElementById('selectCityToAdd');
    var selected = select.options[select.selectedIndex];
    var key = selected.value;
    var label = selected.textContent;
    app.getForecast(key, label);
    app.selectedCities.push({key: key, label: label});
    app.saveCityPreferences({key: key, label: label});
    app.toggleAddDialog(false);
  });

  /* Event listener for cancel button in add city dialog */
  document.getElementById('butAddCancel').addEventListener('click', function() {
    app.toggleAddDialog(false);
  });


  /*****************************************************************************
   *
   * Methods to update/refresh the UI
   *
   ****************************************************************************/

  app.saveCityPreferences = function(city) {
      localforage.getItem('cities').then(function (value) {
          var updatedList =  value || [];
          updatedList.push(city);
          localforage.setItem('cities', updatedList);
          console.log("added cities to list", updatedList);
      }).catch(function (err) {
          console.log(err.message)
      });
  };

    app.loadCityPreferences = function() {
        localforage.getItem('cities').then(function (value) {
            console.log("values is", value);
            if (value == null) {
                app.updateForecastCard(injectedForecast);
            }
            else {
                value.forEach((city) => {
                    app.getForecast(city.key, city.label);
                });
            }
        }).catch(function (err) {
            console.log(err.message)
        });
    };

  // Toggles the visibility of the add new city dialog.
  app.toggleAddDialog = function(visible) {
    if (visible) {
      app.addDialog.classList.add('dialog-container--visible');
    } else {
      app.addDialog.classList.remove('dialog-container--visible');
    }
  };

  // Updates a weather card with the latest weather forecast. If the card
  // doesn't already exist, it's cloned from the template.
  app.updateForecastCard = function(data) {
    var card = app.visibleCards[data.key];
    if (!card) {
      card = app.cardTemplate.cloneNode(true);
      card.classList.remove('cardTemplate');
      card.querySelector('.location').textContent = data.label;
      card.removeAttribute('hidden');
      app.container.appendChild(card);
      app.visibleCards[data.key] = card;
    }
    card.querySelector('.description').textContent = data.currently.summary;
    card.querySelector('.date').textContent =
      new Date(data.currently.time * 1000);
    card.querySelector('.current .icon').classList.add(data.currently.icon);
    card.querySelector('.current .temperature .value').textContent =
      Math.round(data.currently.temperature);
    card.querySelector('.current .feels-like .value').textContent =
      Math.round(data.currently.apparentTemperature);
    card.querySelector('.current .precip').textContent =
      Math.round(data.currently.precipProbability * 100) + '%';
    card.querySelector('.current .humidity').textContent =
      Math.round(data.currently.humidity * 100) + '%';
    card.querySelector('.current .wind .value').textContent =
      Math.round(data.currently.windSpeed);
    card.querySelector('.current .wind .direction').textContent =
      data.currently.windBearing;
    var nextDays = card.querySelectorAll('.future .oneday');
    var today = new Date();
    today = today.getDay();
    for (var i = 0; i < 7; i++) {
      var nextDay = nextDays[i];
      var daily = data.daily.data[i];
      if (daily && nextDay) {
        nextDay.querySelector('.date').textContent =
          app.daysOfWeek[(i + today) % 7];
        nextDay.querySelector('.icon').classList.add(daily.icon);
        nextDay.querySelector('.temp-high .value').textContent =
          Math.round(daily.temperatureMax);
        nextDay.querySelector('.temp-low .value').textContent =
          Math.round(daily.temperatureMin);
      }
    }
    if (app.isLoading) {
      app.spinner.setAttribute('hidden', true);
      app.container.removeAttribute('hidden');
      app.isLoading = false;
    }
  };


  /*****************************************************************************
   *
   * Methods for dealing with the model
   *
   ****************************************************************************/

  // Gets a forecast for a specific city and update the card with the data
  app.getForecast = function(key, label) {
    var url = weatherAPIUrlBase + key + '.json';

    if ('caches' in window) {
          caches.match(url).then(function(response) {
              if (response) {
                  console.log("Loading data from cache");
                  response.json().then(function(json) {
                      json.key = key;
                      json.label = label;
                      app.updateForecastCard(json);
                  });
              }
          });
      }

    // Make the XHR to get the data, then update the card
    var request = new XMLHttpRequest();
    request.onreadystatechange = function() {
      if (request.readyState === XMLHttpRequest.DONE) {
        if (request.status === 200) {
            var response = JSON.parse(request.response);
            response.key = key;
            response.label = label;
            app.completedRequest = true
            app.updateForecastCard(response);
        }
      }
    };

    try {
        request.open('GET', url);
        request.send();
    }
    catch (e) {
        console.error("Unexpected error", e);
    }
  };

  // Iterate all of the cards and attempt to get the latest forecast data
  app.updateForecasts = function() {
    var keys = Object.keys(app.visibleCards);
    keys.forEach(function(key) {
      app.getForecast(key);
    });
  };

  app.urlB64ToUint8Array = function(base64String) {
      const padding = '='.repeat((4 - base64String.length % 4) % 4);
      const base64 = (base64String + padding)
          .replace(/\-/g, '+')
          .replace(/_/g, '/');

      const rawData = window.atob(base64);
      const outputArray = new Uint8Array(rawData.length);

      for (let i = 0; i < rawData.length; ++i) {
          outputArray[i] = rawData.charCodeAt(i);
      }
      return outputArray;
  };

  app.subscribeUser = function() {
          const applicationServerKey = app.urlB64ToUint8Array(applicationServerPublicKey);
          app.pushService.pushManager.subscribe({
              userVisibleOnly: true,
              applicationServerKey: applicationServerKey
          })
              .then((subscription) => {
                  console.log('User is subscribed:', JSON.stringify(subscription));
                  // todo send subscription to server
              })
              .catch(function(err) {
                  console.log('Failed to subscribe the user: ', err);
              });
      };

  app.checkSubscribed = function() {
      if (!('PushManager' in window)) {
          console.error("NO PUSH MANAGER");
          return;
      }
      app.pushService.pushManager.getSubscription()
          .then(function(subscription) {
              var isSubscribed = !(subscription === null);

              if (isSubscribed) {
                  alert("subscription is " + JSON.stringify(subscription));
                  console.log('User IS subscribed.',  JSON.stringify(subscription));
              } else {
                  console.log('User is NOT subscribed.');
                  app.subscribeUser();
              }

          });
  };

    app.loadCityPreferences();

    if ('serviceWorker' in navigator) {
        console.log("IN SERVICE WORKER");
        navigator.serviceWorker
            .register('/service-worker.js')
            .then(function(service) {
                console.debug('Service Worker Registered');
                app.pushService = service;
                app.checkSubscribed();
            });
    }
    else {
        console.log('push manager is not available');
    }

})();
