/**
 * Advanced HTTP Client Module
 * Enhanced HTTP functionality for security testing and API interaction
 */

import axios, { 
  AxiosInstance, 
  AxiosRequestConfig, 
  AxiosResponse, 
  Method,
  InternalAxiosRequestConfig,
  AxiosError
} from 'axios';

export interface RequestLog {
  timestamp: Date;
  method: string;
  url: string;
  status?: number;
  duration: number;
  error?: string;
}

export interface AdvancedHttpOptions extends AxiosRequestConfig {
  logRequests?: boolean;
  retryCount?: number;
  retryDelay?: number;
  followRedirects?: boolean;
  maxRedirects?: number;
  timeout?: number;
}

export class AdvancedHttpClient {
  private client: AxiosInstance;
  private requestLogs: RequestLog[] = [];
  private options: AdvancedHttpOptions;

  constructor(options?: AdvancedHttpOptions) {
    this.options = {
      logRequests: false,
      retryCount: 0,
      retryDelay: 1000,
      followRedirects: true,
      maxRedirects: 5,
      timeout: 30000,
      ...options,
    };

    this.client = axios.create({
      timeout: this.options.timeout,
      maxRedirects: this.options.followRedirects ? this.options.maxRedirects : 0,
      validateStatus: () => true,
      headers: {
        'User-Agent': '1ntruder-HTTPClient/1.0',
        ...options?.headers,
      },
    });

    // Add request interceptor for logging
    if (this.options.logRequests) {
      this.setupLogging();
    }

    // Add response interceptor for retry logic
    this.setupRetryLogic();
  }

  /**
   * Setup request logging
   */
  private setupLogging(): void {
    const startTimeMap = new Map<string, number>();

    this.client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
      const id = `${config.method}-${config.url}-${Date.now()}`;
      startTimeMap.set(id, Date.now());
      return config;
    });

    this.client.interceptors.response.use(
      (response) => {
        const id = `${response.config.method}-${response.config.url}`;
        const startTime = startTimeMap.get(id) || Date.now();
        this.logRequest({
          timestamp: new Date(),
          method: response.config.method?.toUpperCase() || 'UNKNOWN',
          url: response.config.url || '',
          status: response.status,
          duration: Date.now() - startTime,
        });
        return response;
      },
      (error: AxiosError) => {
        const id = `${error.config?.method}-${error.config?.url}`;
        const startTime = startTimeMap.get(id) || Date.now();
        this.logRequest({
          timestamp: new Date(),
          method: (error.config as any)?.method?.toUpperCase() || 'UNKNOWN',
          url: (error.config as any)?.url || '',
          status: error.response?.status,
          duration: Date.now() - startTime,
          error: error.message,
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Setup automatic retry logic
   */
  private setupRetryLogic(): void {
    if (this.options.retryCount && this.options.retryCount > 0) {
      this.client.interceptors.response.use(
        (response) => response,
        async (error) => {
          const config = error.config;
          
          // Check if we should retry
          if (!config || !this.shouldRetry(error)) {
            return Promise.reject(error);
          }

          config.__retryCount = config.__retryCount || 0;
          
          if (config.__retryCount >= this.options.retryCount!) {
            return Promise.reject(error);
          }

          config.__retryCount++;
          
          // Wait before retrying
          await new Promise(resolve => 
            setTimeout(resolve, this.options.retryDelay)
          );

          return this.client(config);
        }
      );
    }
  }

  /**
   * Determine if request should be retried
   */
  private shouldRetry(error: AxiosError): boolean {
    if (!error.response) {
      // Network errors should be retried
      return true;
    }

    const status = error.response.status;
    
    // Retry on server errors and rate limiting
    return status === 429 || status >= 500;
  }

  /**
   * Log a request
   */
  private logRequest(log: RequestLog): void {
    this.requestLogs.push(log);
    
    // Keep only last 1000 logs
    if (this.requestLogs.length > 1000) {
      this.requestLogs.shift();
    }
  }

  /**
   * Make a GET request
   */
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request('GET', url, config);
  }

  /**
   * Make a POST request
   */
  async post<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.request('POST', url, data, config);
  }

  /**
   * Make a PUT request
   */
  async put<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.request('PUT', url, data, config);
  }

  /**
   * Make a DELETE request
   */
  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request('DELETE', url, config);
  }

  /**
   * Make a PATCH request
   */
  async patch<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return this.request('PATCH', url, data, config);
  }

  /**
   * Make a HEAD request
   */
  async head<T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request('HEAD', url, config);
  }

  /**
   * Make an OPTIONS request
   */
  async options<T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request('OPTIONS', url, config);
  }

  /**
   * Generic request method
   */
  async request<T = any>(
    method: Method | string,
    url: string,
    data?: any,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    const requestConfig: AxiosRequestConfig = {
      ...config,
      method: method as Method,
      url,
      data,
    };

    return this.client.request(requestConfig);
  }

  /**
   * Make multiple requests in parallel
   */
  async batch<T = any>(
    requests: Array<{ method: Method; url: string; data?: any; config?: AxiosRequestConfig }>
  ): Promise<Array<AxiosResponse<T> | Error>> {
    const promises = requests.map(req => 
      this.request(req.method, req.url, req.data, req.config)
        .catch(error => error)
    );

    return Promise.all(promises);
  }

  /**
   * Make sequential requests with delay
   */
  async sequential<T = any>(
    requests: Array<{ method: Method; url: string; data?: any; config?: AxiosRequestConfig }>,
    delayMs: number = 0
  ): Promise<Array<AxiosResponse<T> | Error>> {
    const results: Array<AxiosResponse<T> | Error> = [];

    for (const req of requests) {
      try {
        const result = await this.request(req.method, req.url, req.data, req.config);
        results.push(result);
      } catch (error) {
        results.push(error as Error);
      }

      if (delayMs > 0) {
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }

    return results;
  }

  /**
   * Get request logs
   */
  getLogs(): RequestLog[] {
    return [...this.requestLogs];
  }

  /**
   * Clear request logs
   */
  clearLogs(): void {
    this.requestLogs = [];
  }

  /**
   * Get statistics about requests
   */
  getStats(): {
    total: number;
    successful: number;
    failed: number;
    averageDuration: number;
    byStatus: Record<number, number>;
  } {
    const stats = {
      total: this.requestLogs.length,
      successful: 0,
      failed: 0,
      averageDuration: 0,
      byStatus: {} as Record<number, number>,
    };

    let totalDuration = 0;

    for (const log of this.requestLogs) {
      if (log.error) {
        stats.failed++;
      } else {
        stats.successful++;
      }

      if (log.status) {
        stats.byStatus[log.status] = (stats.byStatus[log.status] || 0) + 1;
      }

      totalDuration += log.duration;
    }

    if (this.requestLogs.length > 0) {
      stats.averageDuration = totalDuration / this.requestLogs.length;
    }

    return stats;
  }

  /**
   * Export logs to JSON
   */
  exportLogs(): string {
    return JSON.stringify(this.requestLogs, null, 2);
  }

  /**
   * Set custom headers for all future requests
   */
  setHeaders(headers: Record<string, string>): void {
    Object.assign(this.client.defaults.headers, headers);
  }

  /**
   * Set base URL for all requests
   */
  setBaseURL(baseURL: string): void {
    this.client.defaults.baseURL = baseURL;
  }

  /**
   * Get the underlying axios instance
   */
  getInstance(): AxiosInstance {
    return this.client;
  }

  /**
   * Test connectivity to a URL
   */
  async testConnectivity(url: string, timeout?: number): Promise<{
    reachable: boolean;
    statusCode?: number;
    responseTime: number;
    error?: string;
  }> {
    const startTime = Date.now();
    
    try {
      const response = await this.client.get(url, {
        timeout: timeout || 5000,
        validateStatus: () => true,
      });

      return {
        reachable: response.status < 500,
        statusCode: response.status,
        responseTime: Date.now() - startTime,
      };
    } catch (error: any) {
      return {
        reachable: false,
        responseTime: Date.now() - startTime,
        error: error.message,
      };
    }
  }

  /**
   * Check if a URL returns specific content
   */
  async checkContent(
    url: string, 
    patterns: string[] | RegExp[],
    allMatch: boolean = false
  ): Promise<{
    matches: boolean;
    matchedPatterns: Array<string | RegExp>;
    unmatchedPatterns: Array<string | RegExp>;
  }> {
    try {
      const response = await this.client.get(url, {
        timeout: 10000,
        validateStatus: () => true,
      });

      const bodyStr = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);

      const matched: Array<string | RegExp> = [];
      const unmatched: Array<string | RegExp> = [];

      for (const pattern of patterns) {
        const regex = pattern instanceof RegExp ? pattern : new RegExp(pattern);
        if (regex.test(bodyStr)) {
          matched.push(pattern);
        } else {
          unmatched.push(pattern);
        }
      }

      return {
        matches: allMatch ? unmatched.length === 0 : matched.length > 0,
        matchedPatterns: matched,
        unmatchedPatterns: unmatched,
      };
    } catch (error: any) {
      return {
        matches: false,
        matchedPatterns: [],
        unmatchedPatterns: patterns,
      };
    }
  }
}

export default AdvancedHttpClient;
