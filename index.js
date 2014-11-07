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

var dockerAnalyzer = require('nscale-docker-ssh-analyzer');

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

  Object.keys(system.topology.containers).filter(function(id) {
    return system.topology.containers[id].containedBy === id;
  }).reduce(function(acc, id) {
    var original = system.topology.containers[id].specific;
    var ip = original.privateIpAddress || original.ipAddress || original.ipaddress;

    acc[id] = {
      id: id,
      containedBy: id,
      name: id,
      contains: [],
      type: 'blank-container',
      specific: {
        privateIpAddress: ip
      }
    };

    return acc;
  }, result.topology.containers);

  var docker = dockerAnalyzer(system);
  docker(config, result, function(err) {
    if (err) { return cb(err); }
    cb(null, result);
  });
};

