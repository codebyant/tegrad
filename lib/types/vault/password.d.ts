export declare const MIN_PASSWORD_LENGTH = 12;
export declare const MIN_PASSWORD_SCORE = 3;
export interface ValidatePasswordOptions {
    readonly userInputs?: readonly string[];
}
export type PasswordValidationResult = {
    readonly ok: true;
} | {
    readonly ok: false;
    readonly reason: "too_short" | "too_weak";
};
export declare function validatePassword(password: string, options?: ValidatePasswordOptions): PasswordValidationResult;
