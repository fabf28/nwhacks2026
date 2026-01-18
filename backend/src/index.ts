import dotenv from 'dotenv';
dotenv.config();

import Fastify from 'fastify';
import cors from '@fastify/cors';
import { Server } from 'socket.io';
import { scanUrl } from './services/scanner';
import { chat, ChatRequest } from './services/gemini';

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

    socket.on('start-scan', async (data: { url: string; deepScan?: boolean }) => {

        try {
            // Run the scan with progress updates
            const deepScan = data.deepScan === true;
            console.log(`Scan requested for: ${data.url} ${deepScan ? '(DEEP SCAN)' : ''}`);
            await scanUrl(data.url, (update) => {
                socket.emit('scan-progress', update);
            }, deepScan);
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
fastify.post<{ Body: { url: string; deepScan?: boolean } }>('/scan', async (request, reply) => {
    const { url, deepScan = false } = request.body;

    if (!url) {
        return reply.status(400).send({ error: 'URL is required' });
    }

    const results: any[] = [];
    await scanUrl(url, (update) => results.push(update), deepScan);

    return { results };
});

// Chat endpoint for AI assistance
fastify.post<{ Body: ChatRequest }>('/api/chat', async (request, reply) => {
    const { message, scanContext, conversationHistory } = request.body;

    if (!message) {
        return reply.status(400).send({ error: 'Message is required' });
    }

    const result = await chat({
        message,
        scanContext: scanContext || null,
        conversationHistory: conversationHistory || [],
    });

    return result;
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
