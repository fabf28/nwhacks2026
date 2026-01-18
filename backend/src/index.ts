import dotenv from 'dotenv';
dotenv.config();

import Fastify from 'fastify';
import cors from '@fastify/cors';
import { Server } from 'socket.io';
import { scanUrl } from './services/scanner';

const fastify = Fastify({ logger: true });

// Enable CORS for frontend
fastify.register(cors, {
    origin: 'http://localhost:5173',
    methods: ['GET', 'POST'],
});

// Socket.io setup
const io = new Server(fastify.server, {
    cors: {
        origin: 'http://localhost:5173',
        methods: ['GET', 'POST'],
    },
});

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('start-scan', async (data: { url: string }) => {
        console.log('Scan requested for:', data.url);

        try {
            // Run the scan with progress updates
            await scanUrl(data.url, (update) => {
                socket.emit('scan-progress', update);
            });
        } catch (error) {
            socket.emit('scan-error', { message: 'Scan failed' });
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Health check endpoint
fastify.get('/health', async () => {
    return { status: 'ok' };
});

// REST endpoint for manual scan trigger
fastify.post<{ Body: { url: string } }>('/scan', async (request, reply) => {
    const { url } = request.body;

    if (!url) {
        return reply.status(400).send({ error: 'URL is required' });
    }

    const results: any[] = [];
    await scanUrl(url, (update) => results.push(update));

    return { results };
});

// Start server
const start = async () => {
    try {
        await fastify.listen({ port: 3001, host: '0.0.0.0' });
        console.log('Server running on http://localhost:3001');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
