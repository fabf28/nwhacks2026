import Docker from 'dockerode';

export interface DockerScanResult {
  containerId: string;
  ipAddress?: string;
  error?: string;
}

export async function runDockerScan(url: string): Promise<DockerScanResult> {
  const docker = new Docker({ socketPath: '//./pipe/docker_engine' });

  try {
    await new Promise<void>((resolve, reject) => {
      docker.pull('alpine:latest', (err: any, stream: any) => {
        if (err) return reject(err);
        docker.modem.followProgress(stream, (err: any) => {
          if (err) reject(err);
          else resolve();
        });
      });
    });

    const container = await docker.createContainer({
      Image: 'alpine',
      Cmd: ['sleep', '5'],
      HostConfig: {
        AutoRemove: true,
      },
    });

    await container.start();

    const info = await container.inspect();
    const ipAddress = info.NetworkSettings?.IPAddress || 'No IP assigned';
    const containerId = info.Id.substring(0, 12);

    return {
      containerId,
      ipAddress,
    };
  } catch (error) {
    return {
      containerId: '',
      error: error instanceof Error ? error.message : 'Docker scan failed',
    };
  }
}
