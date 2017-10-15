const { Router } = require('engined-grpc');
const path = require('path');
const gRPCHandlers = require('../grpc');

module.exports = (opts = {}) => {

	const RouterService = Router({
		memberAgent: opts.memberAgent || 'default',
		protoPath: opts.protoPath || null,
		protoFiles: [
			path.join(__dirname, '..', 'proto', 'Member.proto')
		]
	});

	return class gRPCService extends RouterService {

		async initialize(grpcAgent) {

			Object.values(gRPCHandlers).forEach((handler) => {
				handler(this);
			});

		}
	};
};
