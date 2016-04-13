(function() {
    'use strict';

    angular
        .module('jhipsterApp')
        .factory('SsoService', Account);

    Account.$inject = ['$resource'];

    function Account ($resource) {
        var service = $resource('user', {}, {
            'get': { method: 'GET', params: {}, isArray: false,
                interceptor: {
                    response: function(response) {
                        // expose response
                        return response;
                    }
                }
            }
        });

        return service;
    }
})();
