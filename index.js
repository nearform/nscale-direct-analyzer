/*
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

'use strict';

var _ = require('lodash');
var dockerAnalyzer = require('nscale-docker-ssh-analyzer');
var allowedTypes = [
  'docker',
  'blank-container'
];

/**
 * run an analysis over direct links.
 *
 * config (required):
 *  "user":               common user name for login to aws systems (required)
 *  "identityFile":       AWS pem file (required)
 *
 *
 * system (required): the latest system definition, can be null
 */
exports.analyze = function analyze(config, system, cb) {
  system = system || {};

  var result = {
    'name': system.name || config.name,
    'namespace': system.namespace || config.namespace,
    'id': system.systemId || config.systemId,
    'containerDefinitions': [],
    'topology': {
      'containers': {}
    }
  };

  Object.keys(system.topology.containers).reduce(function(acc, id) {
    var original = system.topology.containers[id].specific;
    var ip = original.privateIpAddress || original.ipAddress || original.ipaddress;
    var parentId = system.topology.containers[id].containedBy;

    if (!ip) {
      return acc;
    }

    if (id !== parentId) {
      acc[parentId] = system.topology.containers[parentId];
    }

    acc[id] = {
      id: id,
      containedBy: parentId,
      name: id,
      contains: [],
      type: 'blank-container',
      specific: {
        privateIpAddress: ip
      }
    };

    return acc;
  }, result.topology.containers);

  var docker = dockerAnalyzer(config, system);
  docker(config, result, function(err) {
    if (err) { return cb(err); }
    cb(null, result);
  });
};



/**
 * Checks if this analyzer can analyze the given system.
 * A direct-analyzer can analyze if it contains docker or process
 * containers, and blank-containers with an IP address.
 *
 */
exports.canAnalyze = function canAnalyze(system) {
  var result = _.some(system.topology.containers, function(cont) {
    var rightType = allowedTypes.indexOf(cont.type) >= 0;
    var hasIp = !!(
                  cont.type === 'blank-container' &&
                  cont.specific &&
                  (
                    cont.specific.ipAddress ||
                    cont.specific.ipaddress ||
                    cont.specific.privateIpAddress
                  )
                );
    return rightType && hasIp;
  });

  result = result && _.every(system.topology.containers, function(cont) {
    return allowedTypes.indexOf(cont.type) >= 0;
  });

  return result;
};

