(function() {
    'use strict';

    angular
        .module('jhipsterApp', [
            'ngStorage',
            'tmh.dynamicLocale',
            'pascalprecht.translate',
            'ngResource',
            'ngCookies',
            'ngAria',
            'ngCacheBuster',
            'ngFileUpload',
            'ui.bootstrap',
            'ui.bootstrap.datetimepicker',
            'ui.router',
            'infinite-scroll',
            // jhipster-needle-angularjs-add-module JHipster will add new module here
            'angular-loading-bar'
        ])
        .run(run);

    run.$inject = ['stateHandler', 'translationHandler', 'Principal'];

    function run(stateHandler, translationHandler, Principal) {
        Principal.getUser();
        stateHandler.initialize();
        translationHandler.initialize();
    }
})();
